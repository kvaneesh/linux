/*
 * PPC Huge TLB Page Support for Book3E MMU
 *
 * Copyright (C) 2009 David Gibson, IBM Corporation.
 * Copyright (C) 2011 Becky Bruce, Freescale Semiconductor
 *
 */
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/bootmem.h>
#include <linux/moduleparam.h>
#include <linux/memblock.h>
#include <asm/tlb.h>
#include <asm/setup.h>

/*
 * Tracks gpages after the device tree is scanned and before the
 * huge_boot_pages list is ready.  On non-Freescale implementations, this is
 * just used to track 16G pages and so is a single array.  FSL-based
 * implementations may have more than one gpage size, so we need multiple
 * arrays
 */
#ifdef CONFIG_PPC_FSL_BOOK3E
#define MAX_NUMBER_GPAGES	128
struct psize_gpages {
	u64 gpage_list[MAX_NUMBER_GPAGES];
	unsigned int nr_gpages;
};
static struct psize_gpages gpage_freearray[MMU_PAGE_COUNT];
#endif

/*
 * These macros define how to determine which level of the page table holds
 * the hpdp.
 */
#ifdef CONFIG_PPC_FSL_BOOK3E
#define HUGEPD_PGD_SHIFT PGDIR_SHIFT
#define HUGEPD_PUD_SHIFT PUD_SHIFT
#else
#define HUGEPD_PGD_SHIFT PUD_SHIFT
#define HUGEPD_PUD_SHIFT PMD_SHIFT
#endif

#ifdef CONFIG_PPC_FSL_BOOK3E
#ifdef CONFIG_PPC64
static inline int tlb1_next(void)
{
	struct paca_struct *paca = get_paca();
	struct tlb_core_data *tcd;
	int this, next;

	tcd = paca->tcd_ptr;
	this = tcd->esel_next;

	next = this + 1;
	if (next >= tcd->esel_max)
		next = tcd->esel_first;

	tcd->esel_next = next;
	return this;
}
#else
static inline int tlb1_next(void)
{
	int index, ncams;

	ncams = mfspr(SPRN_TLB1CFG) & TLBnCFG_N_ENTRY;

	index = this_cpu_read(next_tlbcam_idx);

	/* Just round-robin the entries and wrap when we hit the end */
	if (unlikely(index == ncams - 1))
		__this_cpu_write(next_tlbcam_idx, tlbcam_index);
	else
		__this_cpu_inc(next_tlbcam_idx);

	return index;
}
#endif /* !PPC64 */
#endif /* FSL */

static inline int mmu_get_tsize(int psize)
{
	return mmu_psize_defs[psize].enc;
}

static inline int book3e_tlb_exists(unsigned long ea, unsigned long pid)
{
	int found = 0;

	mtspr(SPRN_MAS6, pid << 16);
	if (mmu_has_feature(MMU_FTR_USE_TLBRSRV)) {
		asm volatile(
			"li	%0,0\n"
			"tlbsx.	0,%1\n"
			"bne	1f\n"
			"li	%0,1\n"
			"1:\n"
			: "=&r"(found) : "r"(ea));
	} else {
		asm volatile(
			"tlbsx	0,%1\n"
			"mfspr	%0,0x271\n"
			"srwi	%0,%0,31\n"
			: "=&r"(found) : "r"(ea));
	}

	return found;
}

void book3e_hugetlb_preload(struct vm_area_struct *vma, unsigned long ea,
			    pte_t pte)
{
	unsigned long mas1, mas2;
	u64 mas7_3;
	unsigned long psize, tsize, shift;
	unsigned long flags;
	struct mm_struct *mm;

#ifdef CONFIG_PPC_FSL_BOOK3E
	int index;
#endif

	if (unlikely(is_kernel_addr(ea)))
		return;

	mm = vma->vm_mm;

#ifdef CONFIG_PPC_MM_SLICES
	psize = get_slice_psize(mm, ea);
	tsize = mmu_get_tsize(psize);
	shift = mmu_psize_defs[psize].shift;
#else
	psize = vma_mmu_pagesize(vma);
	shift = __ilog2(psize);
	tsize = shift - 10;
#endif

	/*
	 * We can't be interrupted while we're setting up the MAS
	 * regusters or after we've confirmed that no tlb exists.
	 */
	local_irq_save(flags);

	if (unlikely(book3e_tlb_exists(ea, mm->context.id))) {
		local_irq_restore(flags);
		return;
	}

#ifdef CONFIG_PPC_FSL_BOOK3E
	/* We have to use the CAM(TLB1) on FSL parts for hugepages */
	index = tlb1_next();
	mtspr(SPRN_MAS0, MAS0_ESEL(index) | MAS0_TLBSEL(1));
#endif

	mas1 = MAS1_VALID | MAS1_TID(mm->context.id) | MAS1_TSIZE(tsize);
	mas2 = ea & ~((1UL << shift) - 1);
	mas2 |= (pte_val(pte) >> PTE_WIMGE_SHIFT) & MAS2_WIMGE_MASK;
	mas7_3 = (u64)pte_pfn(pte) << PAGE_SHIFT;
	mas7_3 |= (pte_val(pte) >> PTE_BAP_SHIFT) & MAS3_BAP_MASK;
	if (!pte_dirty(pte))
		mas7_3 &= ~(MAS3_SW|MAS3_UW);

	mtspr(SPRN_MAS1, mas1);
	mtspr(SPRN_MAS2, mas2);

	if (mmu_has_feature(MMU_FTR_USE_PAIRED_MAS)) {
		mtspr(SPRN_MAS7_MAS3, mas7_3);
	} else {
		if (mmu_has_feature(MMU_FTR_BIG_PHYS))
			mtspr(SPRN_MAS7, upper_32_bits(mas7_3));
		mtspr(SPRN_MAS3, lower_32_bits(mas7_3));
	}

	asm volatile ("tlbwe");

	local_irq_restore(flags);
}

void flush_hugetlb_page(struct vm_area_struct *vma, unsigned long vmaddr)
{
	struct hstate *hstate = hstate_file(vma->vm_file);
	unsigned long tsize = huge_page_shift(hstate) - 10;

	__flush_tlb_page(vma->vm_mm, vmaddr, tsize, 0);
}

static int __hugepte_alloc(struct mm_struct *mm, hugepd_t *hpdp,
			   unsigned long address, unsigned pdshift, unsigned pshift)
{
	struct kmem_cache *cachep;
	pte_t *new;

	int i;
	int num_hugepd = 1 << (pshift - pdshift);
	cachep = hugepte_cache;

	new = kmem_cache_zalloc(cachep, GFP_KERNEL|__GFP_REPEAT);

	BUG_ON(pshift > HUGEPD_SHIFT_MASK);
	BUG_ON((unsigned long)new & HUGEPD_SHIFT_MASK);

	if (! new)
		return -ENOMEM;

	spin_lock(&mm->page_table_lock);
	/*
	 * We have multiple higher-level entries that point to the same
	 * actual pte location.  Fill in each as we go and backtrack on error.
	 * We need all of these so the DTLB pgtable walk code can find the
	 * right higher-level entry without knowing if it's a hugepage or not.
	 */
	for (i = 0; i < num_hugepd; i++, hpdp++) {
		if (unlikely(!hugepd_none(*hpdp)))
			break;
		else
			/* We use the old format for PPC_FSL_BOOK3E */
			hpdp->pd = ((unsigned long)new & ~PD_HUGE) | pshift;
	}
	/* If we bailed from the for loop early, an error occurred, clean up */
	if (i < num_hugepd) {
		for (i = i - 1 ; i >= 0; i--, hpdp--)
			hpdp->pd = 0;
		kmem_cache_free(cachep, new);
	}
	spin_unlock(&mm->page_table_lock);
	return 0;
}

pte_t *huge_pte_alloc(struct mm_struct *mm, unsigned long addr, unsigned long sz)
{
	pgd_t *pg;
	pud_t *pu;
	pmd_t *pm;
	hugepd_t *hpdp = NULL;
	unsigned pshift = __ffs(sz);
	unsigned pdshift = PGDIR_SHIFT;

	addr &= ~(sz-1);

	pg = pgd_offset(mm, addr);

	if (pshift >= HUGEPD_PGD_SHIFT) {
		hpdp = (hugepd_t *)pg;
	} else {
		pdshift = PUD_SHIFT;
		pu = pud_alloc(mm, pg, addr);
		if (pshift >= HUGEPD_PUD_SHIFT) {
			hpdp = (hugepd_t *)pu;
		} else {
			pdshift = PMD_SHIFT;
			pm = pmd_alloc(mm, pu, addr);
			hpdp = (hugepd_t *)pm;
		}
	}

	if (!hpdp)
		return NULL;

	BUG_ON(!hugepd_none(*hpdp) && !hugepd_ok(*hpdp));

	if (hugepd_none(*hpdp) && __hugepte_alloc(mm, hpdp, addr, pdshift, pshift))
		return NULL;

	return hugepte_offset(*hpdp, addr, pdshift);
}

#ifdef CONFIG_PPC_FSL_BOOK3E
/* Build list of addresses of gigantic pages.  This function is used in early
 * boot before the buddy allocator is setup.
 */
void add_gpage(u64 addr, u64 page_size, unsigned long number_of_pages)
{
	unsigned int idx = shift_to_mmu_psize(__ffs(page_size));
	int i;

	if (addr == 0)
		return;

	gpage_freearray[idx].nr_gpages = number_of_pages;

	for (i = 0; i < number_of_pages; i++) {
		gpage_freearray[idx].gpage_list[i] = addr;
		addr += page_size;
	}
}

/*
 * Moves the gigantic page addresses from the temporary list to the
 * huge_boot_pages list.
 */
int alloc_bootmem_huge_page(struct hstate *hstate)
{
	struct huge_bootmem_page *m;
	int idx = shift_to_mmu_psize(huge_page_shift(hstate));
	int nr_gpages = gpage_freearray[idx].nr_gpages;

	if (nr_gpages == 0)
		return 0;

#ifdef CONFIG_HIGHMEM
	/*
	 * If gpages can be in highmem we can't use the trick of storing the
	 * data structure in the page; allocate space for this
	 */
	m = memblock_virt_alloc(sizeof(struct huge_bootmem_page), 0);
	m->phys = gpage_freearray[idx].gpage_list[--nr_gpages];
#else
	m = phys_to_virt(gpage_freearray[idx].gpage_list[--nr_gpages]);
#endif

	list_add(&m->list, &huge_boot_pages);
	gpage_freearray[idx].nr_gpages = nr_gpages;
	gpage_freearray[idx].gpage_list[nr_gpages] = 0;
	m->hstate = hstate;

	return 1;
}
/*
 * Scan the command line hugepagesz= options for gigantic pages; store those in
 * a list that we use to allocate the memory once all options are parsed.
 */

unsigned long gpage_npages[MMU_PAGE_COUNT];

static int __init do_gpage_early_setup(char *param, char *val,
				       const char *unused, void *arg)
{
	static phys_addr_t size;
	unsigned long npages;

	/*
	 * The hugepagesz and hugepages cmdline options are interleaved.  We
	 * use the size variable to keep track of whether or not this was done
	 * properly and skip over instances where it is incorrect.  Other
	 * command-line parsing code will issue warnings, so we don't need to.
	 *
	 */
	if ((strcmp(param, "default_hugepagesz") == 0) ||
	    (strcmp(param, "hugepagesz") == 0)) {
		size = memparse(val, NULL);
	} else if (strcmp(param, "hugepages") == 0) {
		if (size != 0) {
			if (sscanf(val, "%lu", &npages) <= 0)
				npages = 0;
			if (npages > MAX_NUMBER_GPAGES) {
				pr_warn("MMU: %lu pages requested for page "
					"size %llu KB, limiting to "
					__stringify(MAX_NUMBER_GPAGES) "\n",
					npages, size / 1024);
				npages = MAX_NUMBER_GPAGES;
			}
			gpage_npages[shift_to_mmu_psize(__ffs(size))] = npages;
			size = 0;
		}
	}
	return 0;
}


/*
 * This function allocates physical space for pages that are larger than the
 * buddy allocator can handle.  We want to allocate these in highmem because
 * the amount of lowmem is limited.  This means that this function MUST be
 * called before lowmem_end_addr is set up in MMU_init() in order for the lmb
 * allocate to grab highmem.
 */
void __init reserve_hugetlb_gpages(void)
{
	static __initdata char cmdline[COMMAND_LINE_SIZE];
	phys_addr_t size, base;
	int i;

	strlcpy(cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_args("hugetlb gpages", cmdline, NULL, 0, 0, 0,
			NULL, &do_gpage_early_setup);

	/*
	 * Walk gpage list in reverse, allocating larger page sizes first.
	 * Skip over unsupported sizes, or sizes that have 0 gpages allocated.
	 * When we reach the point in the list where pages are no longer
	 * considered gpages, we're done.
	 */
	for (i = MMU_PAGE_COUNT-1; i >= 0; i--) {
		if (mmu_psize_defs[i].shift == 0 || gpage_npages[i] == 0)
			continue;
		else if (mmu_psize_to_shift(i) < (MAX_ORDER + PAGE_SHIFT))
			break;

		size = (phys_addr_t)(1ULL << mmu_psize_to_shift(i));
		base = memblock_alloc_base(size * gpage_npages[i], size,
					   MEMBLOCK_ALLOC_ANYWHERE);
		add_gpage(base, size, gpage_npages[i]);
	}
}

#define HUGEPD_FREELIST_SIZE \
	((PAGE_SIZE - sizeof(struct hugepd_freelist)) / sizeof(pte_t))

struct hugepd_freelist {
	struct rcu_head	rcu;
	unsigned int index;
	void *ptes[0];
};

static DEFINE_PER_CPU(struct hugepd_freelist *, hugepd_freelist_cur);

static void hugepd_free_rcu_callback(struct rcu_head *head)
{
	struct hugepd_freelist *batch =
		container_of(head, struct hugepd_freelist, rcu);
	unsigned int i;

	for (i = 0; i < batch->index; i++)
		kmem_cache_free(hugepte_cache, batch->ptes[i]);

	free_page((unsigned long)batch);
}

void hugepd_free(struct mmu_gather *tlb, void *hugepte)
{
	struct hugepd_freelist **batchp;

	batchp = this_cpu_ptr(&hugepd_freelist_cur);

	if (atomic_read(&tlb->mm->mm_users) < 2 ||
	    cpumask_equal(mm_cpumask(tlb->mm),
			  cpumask_of(smp_processor_id()))) {
		kmem_cache_free(hugepte_cache, hugepte);
        put_cpu_var(hugepd_freelist_cur);
		return;
	}

	if (*batchp == NULL) {
		*batchp = (struct hugepd_freelist *)__get_free_page(GFP_ATOMIC);
		(*batchp)->index = 0;
	}

	(*batchp)->ptes[(*batchp)->index++] = hugepte;
	if ((*batchp)->index == HUGEPD_FREELIST_SIZE) {
		call_rcu_sched(&(*batchp)->rcu, hugepd_free_rcu_callback);
		*batchp = NULL;
	}
	put_cpu_var(hugepd_freelist_cur);
}
#endif
