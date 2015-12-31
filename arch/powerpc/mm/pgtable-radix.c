/*
 * page table handling routines for radix page table
 *
 *  Copyright (C) 2015 Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 */
#include <linux/sched.h>
#include <linux/memblock.h>

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/dma.h>
#include <asm/machdep.h>
#include <asm/mmu.h>
#include <asm/firmware.h>

#include <trace/events/thp.h>

struct prtb_entry *process_tb;
struct patb_entry *partition_tb;

static int native_update_partition_table(u64 patb1)
{
	partition_tb->patb1 = cpu_to_be64(patb1);
	return 0;
}

static __ref void *early_alloc_pgtable(unsigned long size)
{
	void *pt;

	pt = __va(memblock_alloc_base(size, size, __pa(MAX_DMA_ADDRESS)));
	memset(pt, 0, size);

	return pt;
}

/*
 * set_pte stores a linux PTE into the linux page table.
 */
void set_rpte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
		 pte_t pte)
{
	/*
	 * When handling numa faults, we already have the pte marked
	 * _PAGE_PRESENT, but we can be sure that it is not in hpte.
	 * Hence we can use set_pte_at for them.
	 */
	VM_WARN_ON(rpte_present(*ptep));

#if 0 /* Do we need to filter ? */
	/* Note: mm->context.id might not yet have been assigned as
	 * this context might not have been activated yet when this
	 * is called.
	 */
	pte = set_pte_filter(pte);
#endif
	/* Perform the setting of the PTE */
	__set_rpte_at(mm, addr, ptep, pte, 0);
}

int map_radix_kernel_page(unsigned long ea, unsigned long pa,
			  pgprot_t flags,
			  unsigned int map_page_size)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;
	/*
	 * Make sure task size is correct as per the max adddr
	 */
	BUILD_BUG_ON(TASK_SIZE_USER64 > RPGTABLE_RANGE);
	if (slab_is_available()) {
		pgdp = pgd_offset_k(ea);
		pudp = pud_alloc(&init_mm, pgdp, ea);
		if (!pudp)
			return -ENOMEM;
		if (map_page_size == PUD_SIZE) {
			ptep = (pte_t *)pudp;
			goto set_the_pte;
		}
		pmdp = pmd_alloc(&init_mm, pudp, ea);
		if (!pmdp)
			return -ENOMEM;
		if (map_page_size == PMD_SIZE) {
			ptep = (pte_t *)pudp;
			goto set_the_pte;
		}
		ptep = pte_alloc_kernel(pmdp, ea);
		if (!ptep)
			return -ENOMEM;
	} else {
		pgdp = pgd_offset_k(ea);
		if (pgd_none(*pgdp)) {
			pudp = early_alloc_pgtable(RPUD_TABLE_SIZE);
			BUG_ON(pudp == NULL);
			rpgd_populate(&init_mm, pgdp, pudp);
		}
		pudp = pud_offset(pgdp, ea);
		if (map_page_size == PUD_SIZE) {
			ptep = (pte_t *)pudp;
			goto set_the_pte;
		}
		if (pud_none(*pudp)) {
			pmdp = early_alloc_pgtable(RPMD_TABLE_SIZE);
			BUG_ON(pmdp == NULL);
			rpud_populate(&init_mm, pudp, pmdp);
		}
		pmdp = pmd_offset(pudp, ea);
		if (map_page_size == PMD_SIZE) {
			ptep = (pte_t *)pudp;
			goto set_the_pte;
		}
		if (!pmd_present(*pmdp)) {
			ptep = early_alloc_pgtable(PAGE_SIZE);
			BUG_ON(ptep == NULL);
			rpmd_populate_kernel(&init_mm, pmdp, ptep);
		}
		ptep = pte_offset_kernel(pmdp, ea);
	}

set_the_pte:
	set_rpte_at(&init_mm, ea, ptep, pfn_pte(pa >> PAGE_SHIFT, flags));
	smp_wmb();
	return 0;
}

static void __init radix_init_pgtable(void)
{
	u64 base, end;
	unsigned long rts_field;
	struct memblock_region *reg;
	unsigned long linear_page_size;
	unsigned long total_size;

	pr_info("Mapping linear mapping in radix tree...\n");
	total_size = memblock_phys_mem_size();
	if (total_size < PUD_SIZE)
		if (total_size < PMD_SIZE)
			linear_page_size = PAGE_SIZE;
		else if (mmu_psize_defs[MMU_PAGE_2M].shift) {
			linear_page_size = PMD_SIZE;
			mmu_linear_psize = MMU_PAGE_2M;
		} else
			linear_page_size = PAGE_SIZE;
	else if (mmu_psize_defs[MMU_PAGE_1G].shift) {
		linear_page_size = PUD_SIZE;
		mmu_linear_psize = MMU_PAGE_1G;
	} else if (mmu_psize_defs[MMU_PAGE_2M].shift) {
		linear_page_size = PMD_SIZE;
		mmu_linear_psize = MMU_PAGE_2M;
	} else
		linear_page_size = PAGE_SIZE;

	pr_info("Mapping kernel with page_size 0x%lx\n", linear_page_size);
	/* We don't support slb for radix */
	mmu_slb_size = 0;
	/*
	 * Create the linear mapping, using standard page size for now
	 */
	for_each_memblock(memory, reg) {
		base = _ALIGN_UP(reg->base, linear_page_size);
		end = _ALIGN_DOWN(reg->base + reg->size, linear_page_size);

		while (base < end) {
			map_radix_kernel_page((unsigned long)__va(base),
					      base, RPAGE_KERNEL_X,
					      linear_page_size);
			base += linear_page_size;
		}
	}
	/*
	 * Allocate Partition table and process table for the
	 * host.
	 */
	BUILD_BUG_ON_MSG((PRTB_SIZE_SHIFT > 23), "Process table size too large.");
	process_tb = early_alloc_pgtable(1UL << PRTB_SIZE_SHIFT);
	/*
	 * Fill in the process table.
	 * we support 52 bits, hence 52-28 = 24, 11000
	 */
	rts_field = 3ull << PPC_BITLSHIFT(2);
	process_tb->prtb0 = cpu_to_be64(rts_field | __pa(init_mm.pgd) | RPGD_INDEX_SIZE);
	/*
	 * Fill in the partition table, 64k size for process table.
	 */
	ppc_md.update_partition_table(__pa(process_tb) | (PRTB_SIZE_SHIFT - 12) | PATB_GR);
	pr_info("Process table %p and radix root for kernel: %p\n", process_tb, init_mm.pgd);
}

static void __init radix_init_partition_table(void)
{
	unsigned long rts_field;
	/*
	 * we support 52 bits, hence 52-28 = 24, 11000
	 */
	rts_field = 3ull << PPC_BITLSHIFT(2);

	BUILD_BUG_ON_MSG((PATB_SIZE_SHIFT > 24), "Partition table size too large.");
	partition_tb = early_alloc_pgtable(1UL << PATB_SIZE_SHIFT);
	partition_tb->patb0 = cpu_to_be64(rts_field | __pa(init_mm.pgd) |
					  RPGD_INDEX_SIZE | PATB_HR);
	printk("Partition table %p\n", partition_tb);

	memblock_set_current_limit(MEMBLOCK_ALLOC_ANYWHERE);
	/*
	 * update partition table control register,
	 * 64 K size.
	 */
	mtspr(SPRN_PTCR, __pa(partition_tb) | (PATB_SIZE_SHIFT - 12));
}

void __init radix_init_native(void)
{
	ppc_md.update_partition_table = native_update_partition_table;
}

void __init rearly_init_mmu(void)
{
	/*
	 * mmu_linear_psize get update to 1G or 2M if available
	 * We are currently forcing everyting else to PAGE_SIZE.
	 * We could do better with vmemmap_psize.
	 */
#ifdef CONFIG_PPC_64K_PAGES
	mmu_linear_psize = MMU_PAGE_64K;
	mmu_virtual_psize = MMU_PAGE_64K;
	mmu_vmalloc_psize = MMU_PAGE_64K;
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	mmu_vmemmap_psize = MMU_PAGE_64K;
#endif
	mmu_io_psize = MMU_PAGE_64K;
#else
	mmu_linear_psize = MMU_PAGE_4K;
	mmu_virtual_psize = MMU_PAGE_4K;
	mmu_vmalloc_psize = MMU_PAGE_4K;
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	mmu_vmemmap_psize = MMU_PAGE_4K;
#endif
	mmu_io_psize = MMU_PAGE_4K;
#endif
	/*
	 * initialize global variables
	 */
	__kernel_page_prot = RPAGE_KERNEL;
	__page_none = RPAGE_NONE;
	__ptrs_per_pte = PTRS_PER_RPTE;
	__ptrs_per_pmd = PTRS_PER_RPMD;
	__pmd_shift    = RPMD_SHIFT;
#ifndef __PAGETABLE_PUD_FOLDED
	__pud_shift    = RPUD_SHIFT;
#endif
	__pgdir_shift  = RPGDIR_SHIFT;
	__kernel_virt_start = RKERN_VIRT_START;
	__kernel_virt_size = RKERN_VIRT_SIZE;
	vmemmap = (struct page *)RVMEMMAP_BASE;
	__vmalloc_start = RVMALLOC_START;
	__vmalloc_end = RVMALLOC_END;
	__page_no_cache = _RPAGE_NO_CACHE;
	__page_guarded = _RPAGE_GUARDED;
	__page_user = _RPAGE_USER;
	__page_coherent = _RPAGE_COHERENT;
	__page_present = _RPAGE_PRESENT;
	__page_kernel_exec = RPAGE_KERNEL_EXEC;
	ioremap_bot = IOREMAP_BASE;


	mmu_psize_defs[MMU_PAGE_4K].shift = 12;
	mmu_psize_defs[MMU_PAGE_4K].sllp = 0x0000;

	mmu_psize_defs[MMU_PAGE_64K].shift = 16;
	mmu_psize_defs[MMU_PAGE_64K].sllp = 0x0110;

	/* 2M */
	mmu_psize_defs[MMU_PAGE_2M].shift = 21;
	/* FIXME!! Fix sllp based on device tree */
	mmu_psize_defs[MMU_PAGE_2M].sllp = 0x0010;

	/* 1G */
	mmu_psize_defs[MMU_PAGE_1G].shift = 30;
	/* FIXME!! Fix sllp based on device tree */
	mmu_psize_defs[MMU_PAGE_1G].sllp = 0x0020;

	if (!firmware_has_feature(FW_FEATURE_LPAR))
		radix_init_partition_table();

	radix_init_pgtable();
}

void rearly_init_mmu_secondary(void)
{
	/*
	 * update partition table control register, 64 K size.
	 */
	if (!firmware_has_feature(FW_FEATURE_LPAR))
		mtspr(SPRN_PTCR,
		      __pa(partition_tb) | (PATB_SIZE_SHIFT - 12));
}

void rsetup_initial_memory_limit(phys_addr_t first_memblock_base,
				phys_addr_t first_memblock_size)
{
	/* Finally limit subsequent allocations */
	memblock_set_current_limit(first_memblock_base + first_memblock_size);
}

static void pgd_ctor(void *addr)
{
	memset(addr, 0, RPGD_TABLE_SIZE);
}

static void pmd_ctor(void *addr)
{
	memset(addr, 0, RPMD_TABLE_SIZE);
}

void rpgtable_cache_init(void)
{
	pgtable_cache_add(RPGD_INDEX_SIZE, pgd_ctor);
	pgtable_cache_add(RPMD_INDEX_SIZE, pmd_ctor);

	if (!PGT_CACHE(RPGD_INDEX_SIZE) || !PGT_CACHE(RPMD_INDEX_SIZE))
		panic("Couldn't allocate pgtable caches");
	/* PUD_INDEX == PMD_INDEX */
	if (RPUD_INDEX_SIZE && !PGT_CACHE(RPUD_INDEX_SIZE))
		panic("Couldn't allocate pud pgtable caches");
}

pgtable_t rpte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *page;

	page = alloc_page(PGALLOC_GFP);
	if (!page)
		return NULL;
	if (!pgtable_page_ctor(page)) {
		__free_page(page);
		return NULL;
	}
	return page_address(page);
}

static pgprot_t radix_protection_map[16] = {
	__RP000, __RP001, __RP010, __RP011, __RP100, __RP101, __RP110, __RP111,
	__RS000, __RS001, __RS010, __RS011, __RS100, __RS101, __RS110, __RS111
};

pgprot_t rvm_get_page_prot(unsigned long vm_flags)
{
	pgprot_t prot_soa = __pgprot(0);

	if (vm_flags & VM_SAO)
		prot_soa = __pgprot(_RPAGE_SAO);

	return __pgprot(pgprot_val(radix_protection_map[vm_flags &
				(VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)]) |
			pgprot_val(prot_soa));
}
EXPORT_SYMBOL(rvm_get_page_prot);

#ifdef CONFIG_SPARSEMEM_VMEMMAP
void __meminit rvmemmap_create_mapping(unsigned long start,
				      unsigned long page_size,
				      unsigned long phys)
{
	/* Create a PTE encoding */
	unsigned long flags = _RPAGE_PRESENT | _RPAGE_ACCESSED |
				_RPAGE_KERNEL_RW;

	BUG_ON(map_radix_kernel_page(start, phys, __pgprot(flags), page_size));
}

#ifdef CONFIG_MEMORY_HOTPLUG
void rvmemmap_remove_mapping(unsigned long start, unsigned long page_size)
{
	/* FIXME!! intel does more. We should free page tables mapping vmemmap ? */
}
#endif
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/*
 * This is called when relaxing access to a hugepage. It's also called in the page
 * fault path when we don't hit any of the major fault cases, ie, a minor
 * update of _PAGE_ACCESSED, _PAGE_DIRTY, etc... The generic code will have
 * handled those two for us, we additionally deal with missing execute
 * permission here on some processors
 */
int rpmdp_set_access_flags(struct vm_area_struct *vma, unsigned long address,
			    pmd_t *pmdp, pmd_t entry, int dirty)
{
	int changed;
#ifdef CONFIG_DEBUG_VM
	WARN_ON(!rpmd_trans_huge(*pmdp));
	assert_spin_locked(&vma->vm_mm->page_table_lock);
#endif
	changed = !rpmd_same(*(pmdp), entry);
	if (changed) {
		__rptep_set_access_flags(pmdp_ptep(pmdp), pmd_pte(entry));
		/*
		 * Since we are not supporting SW TLB systems, we don't
		 * have any thing similar to flush_tlb_page_nohash()
		 */
	}
	return changed;
}

unsigned long rpmd_hugepage_update(struct mm_struct *mm, unsigned long addr,
				  pmd_t *pmdp, unsigned long clr,
				  unsigned long set)
{

	unsigned long old;

#ifdef CONFIG_DEBUG_VM
	WARN_ON(!rpmd_trans_huge(*pmdp));
	assert_spin_locked(&mm->page_table_lock);
#endif

	old = pmd_val(*pmdp);
	*pmdp = __pmd((old & ~clr) | set);
	trace_hugepage_update(addr, old, clr, set);
	return old;
}

/* FIXME!! we may not need all these kicks */
pmd_t rpmdp_collapse_flush(struct vm_area_struct *vma, unsigned long address,
			pmd_t *pmdp)

{
	pmd_t pmd;

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
	VM_BUG_ON(rpmd_trans_huge(*pmdp));
	/*
	 * khugepaged calls this for normal pmd
	 */
	pmd = *pmdp;
	pmd_clear(pmdp);
	/*
	 * Wait for all pending hash_page to finish. This is needed
	 * in case of subpage collapse. When we collapse normal pages
	 * to hugepage, we first clear the pmd, then invalidate all
	 * the PTE entries. The assumption here is that any low level
	 * page fault will see a none pmd and take the slow path that
	 * will wait on mmap_sem. But we could very well be in a
	 * hash_page with local ptep pointer value. Such a hash page
	 * can result in adding new HPTE entries for normal subpages.
	 * That means we could be modifying the page content as we
	 * copy them to a huge page. So wait for parallel hash_page
	 * to finish before invalidating HPTE entries. We can do this
	 * by sending an IPI to all the cpus and executing a dummy
	 * function there.
	 */
	kick_all_cpus_sync();
	flush_pmd_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
	return pmd;
}
/*
 * We mark the pmd splitting and invalidate all the hpte
 * entries for this hugepage.
 */
void rpmdp_splitting_flush(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp)
{
	unsigned long old;

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);

#ifdef CONFIG_DEBUG_VM
	WARN_ON(!rpmd_trans_huge(*pmdp));
	assert_spin_locked(&vma->vm_mm->page_table_lock);
#endif
	old = pmd_val(*pmdp);
	*pmdp = __pmd(old | _RPAGE_SPLITTING);
	/*
	 * If we didn't had the splitting flag set, go and flush the
	 * HPTE entries.
	 */
	trace_hugepage_splitting(address, old);
	/*
	 * This ensures that generic code that rely on IRQ disabling
	 * to prevent a parallel THP split work as expected.
	 */
	kick_all_cpus_sync();
	flush_pmd_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
}

void rpgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				 pgtable_t pte)
{
	struct page *pgtable = virt_to_page(pte);
	assert_spin_locked(pmd_lockptr(mm, pmdp));

	/* FIFO */
	if (!pmd_huge_pte(mm, pmdp))
		INIT_LIST_HEAD(&pgtable->lru);
	else
		list_add(&pgtable->lru, &pmd_huge_pte(mm, pmdp)->lru);
	pmd_huge_pte(mm, pmdp) = pgtable;
}

/* no "address" argument so destroys page coloring of some arch */
pgtable_t rpgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp)
{
	struct page *pgtable;

	assert_spin_locked(pmd_lockptr(mm, pmdp));

	/* FIFO */
	pgtable = pmd_huge_pte(mm, pmdp);
	if (list_empty(&pgtable->lru))
		pmd_huge_pte(mm, pmdp) = NULL;
	else {
		pmd_huge_pte(mm, pmdp) = list_entry(pgtable->lru.next,
						    struct page, lru);
		list_del(&pgtable->lru);
	}
	return page_address(pgtable);
}
/*
 * set a new huge pmd. We should not be called for updating
 * an existing pmd entry. That should go via pmd_hugepage_update.
 */
void set_rpmd_at(struct mm_struct *mm, unsigned long addr,
		pmd_t *pmdp, pmd_t pmd)
{
#ifdef CONFIG_DEBUG_VM
        WARN_ON(pte_present(pmd_pte(*pmdp)));
	assert_spin_locked(&mm->page_table_lock);
	WARN_ON(!rpmd_trans_huge(pmd));
#endif
	trace_hugepage_set_pmd(addr, pmd_val(pmd));
	return set_rpte_at(mm, addr, pmdp_ptep(pmdp), pmd_pte(pmd));
}

void rpmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
		      pmd_t *pmdp)
{
	rpmd_hugepage_update(vma->vm_mm, address, pmdp,
			     _RPAGE_PRESENT, 0);
	flush_pmd_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
}

static pmd_t pmd_set_protbits(pmd_t pmd, pgprot_t pgprot)
{
	return __pmd(pmd_val(pmd) | pgprot_val(pgprot));
}

pmd_t pfn_rpmd(unsigned long pfn, pgprot_t pgprot)
{
	/* FIXME!! check the pfn shifts */
	unsigned long pmdv;
	/*
	 * For a valid pte, we would have _PAGE_PRESENT always
	 * set. We use this to check THP page at pmd level.
	 * leaf pte for huge page, bottom two bits != 00
	 */
	pmdv = pfn << PAGE_SHIFT;
	return pmd_set_protbits(__pmd(pmdv), pgprot);
}

pmd_t mk_rpmd(struct page *page, pgprot_t pgprot)
{
	return pfn_pmd(page_to_pfn(page), pgprot);
}

pmd_t rpmd_modify(pmd_t pmd, pgprot_t newprot)
{
	unsigned long pmdv;

	pmdv = pmd_val(pmd);
	pmdv &= _RHPAGE_CHG_MASK;
	return pmd_set_protbits(__pmd(pmdv), newprot);
}

pmd_t rpmdp_huge_get_and_clear(struct mm_struct *mm,
			       unsigned long addr, pmd_t *pmdp)
{
	pmd_t old_pmd;
	unsigned long old;

	old = rpmd_hugepage_update(mm, addr, pmdp, ~0UL, 0);
	old_pmd = __pmd(old);
	/*
	 * Serialize against find_linux_pte_or_hugepte which does lock-less
	 * lookup in page tables with local interrupts disabled. For huge pages
	 * it casts pmd_t to pte_t. Since format of pte_t is different from
	 * pmd_t we want to prevent transit from pmd pointing to page table
	 * to pmd pointing to huge page (and back) while interrupts are disabled.
	 * We clear pmd to possibly replace it with page table pointer in
	 * different code paths. So make sure we wait for the parallel
	 * find_linux_pte_or_hugepage to finish.
	 */
	kick_all_cpus_sync();
	return old_pmd;
}

int r_has_transparent_hugepage(void)
{
	BUILD_BUG_ON_MSG((RPMD_SHIFT - PAGE_SHIFT) >= MAX_ORDER,
		"hugepages can't be allocated by the buddy allocator");

	/* For radix 2M at PMD level means thp */
	if (mmu_psize_defs[MMU_PAGE_2M].shift == PMD_SHIFT)
		return 1;
	return 0;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
