/*
 * Copyright IBM Corporation, 2015
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

/*
 * PPC64 THP Support for hash based MMUs
 */
#include <linux/sched.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>

#include "mmu_decl.h"

#define CREATE_TRACE_POINTS
#include <trace/events/thp.h>

#if H_PGTABLE_RANGE > USER_VSID_RANGE
#warning Limited user VSID range means pagetable space is wasted
#endif

#if (TASK_SIZE_USER64 < H_PGTABLE_RANGE) && (TASK_SIZE_USER64 < USER_VSID_RANGE)
#warning TASK_SIZE is smaller than it needs to be.
#endif

#if (TASK_SIZE_USER64 > H_PGTABLE_RANGE)
#warning TASK_SIZE is larger than page table range
#endif

static void pgd_ctor(void *addr)
{
	memset(addr, 0, H_PGD_TABLE_SIZE);
}

static void pud_ctor(void *addr)
{
	memset(addr, 0, H_PUD_TABLE_SIZE);
}

static void pmd_ctor(void *addr)
{
	memset(addr, 0, H_PMD_TABLE_SIZE);
}


void pgtable_cache_init(void)
{
	pgtable_cache_add(H_PGD_INDEX_SIZE, pgd_ctor);
	pgtable_cache_add(H_PMD_CACHE_INDEX, pmd_ctor);
	/*
	 * In all current configs, when the PUD index exists it's the
	 * same size as either the pgd or pmd index except with THP enabled
	 * on book3s 64
	 */
	if (H_PUD_INDEX_SIZE && !PGT_CACHE(H_PUD_INDEX_SIZE))
		pgtable_cache_add(H_PUD_INDEX_SIZE, pud_ctor);

	if (!PGT_CACHE(H_PGD_INDEX_SIZE) || !PGT_CACHE(H_PMD_CACHE_INDEX))
		panic("Couldn't allocate pgtable caches");
	if (H_PUD_INDEX_SIZE && !PGT_CACHE(H_PUD_INDEX_SIZE))
		panic("Couldn't allocate pud pgtable caches");
}

#ifdef CONFIG_SPARSEMEM_VMEMMAP
/*
 * On hash-based CPUs, the vmemmap is bolted in the hash table.
 *
 */
void __meminit vmemmap_create_mapping(unsigned long start,
				      unsigned long page_size,
				      unsigned long phys)
{
	int  mapped = htab_bolt_mapping(start, start + page_size, phys,
					pgprot_val(H_PAGE_KERNEL),
					mmu_vmemmap_psize,
					mmu_kernel_ssize);
	BUG_ON(mapped < 0);
}

#ifdef CONFIG_MEMORY_HOTPLUG
void vmemmap_remove_mapping(unsigned long start,
			    unsigned long page_size)
{
	int mapped = htab_remove_mapping(start, start + page_size,
					 mmu_vmemmap_psize,
					 mmu_kernel_ssize);
	BUG_ON(mapped < 0);
}
#endif
#endif /* CONFIG_SPARSEMEM_VMEMMAP */

void update_mmu_cache(struct vm_area_struct *vma, unsigned long address,
		      pte_t *ptep)
{
	/*
	 * We don't need to worry about _PAGE_PRESENT here because we are
	 * called with either mm->page_table_lock held or ptl lock held
	 */
	unsigned long access = 0, trap;

	/* We only want HPTEs for linux PTEs that have _PAGE_ACCESSED set */
	if (!pte_young(*ptep) || address >= TASK_SIZE)
		return;

	/* We try to figure out if we are coming from an instruction
	 * access fault and pass that down to __hash_page so we avoid
	 * double-faulting on execution of fresh text. We have to test
	 * for regs NULL since init will get here first thing at boot
	 *
	 * We also avoid filling the hash if not coming from a fault
	 */
	if (current->thread.regs == NULL)
		return;
	trap = TRAP(current->thread.regs);
	if (trap == 0x400)
		access |= H_PAGE_EXEC;
	else if (trap != 0x300)
		return;
	hash_preload(vma->vm_mm, address, access, trap);
}

/*
 * map_kernel_page currently only called by __ioremap
 * map_kernel_page adds an entry to the ioremap page table
 * and adds an entry to the HPT, possibly bolting it
 */
int map_kernel_page(unsigned long ea, unsigned long pa, int flags)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	if (slab_is_available()) {
		pgdp = pgd_offset_k(ea);
		pudp = pud_alloc(&init_mm, pgdp, ea);
		if (!pudp)
			return -ENOMEM;
		pmdp = pmd_alloc(&init_mm, pudp, ea);
		if (!pmdp)
			return -ENOMEM;
		ptep = pte_alloc_kernel(pmdp, ea);
		if (!ptep)
			return -ENOMEM;
		set_pte_at(&init_mm, ea, ptep, pfn_pte(pa >> PAGE_SHIFT,
							  __pgprot(flags)));
	} else {
		/*
		 * If the mm subsystem is not fully up, we cannot create a
		 * linux page table entry for this mapping.  Simply bolt an
		 * entry in the hardware page table.
		 *
		 */
		if (htab_bolt_mapping(ea, ea + PAGE_SIZE, pa, flags,
				      mmu_io_psize, mmu_kernel_ssize)) {
			printk(KERN_ERR "Failed to do bolted mapping IO "
			       "memory at %016lx !\n", pa);
			return -ENOMEM;
		}
	}

	smp_wmb();
	return 0;
}

/*
 * We only try to do i/d cache coherency on stuff that looks like
 * reasonably "normal" PTEs. We currently require a PTE to be present
 * and we avoid _PAGE_SPECIAL and _PAGE_NO_CACHE. We also only do that
 * on userspace PTEs
 */
static inline int pte_looks_normal(pte_t pte)
{
	return (pte_val(pte) & (H_PAGE_PRESENT | H_PAGE_SPECIAL |
					H_PAGE_NO_CACHE | H_PAGE_USER)) ==
		(H_PAGE_PRESENT | H_PAGE_USER);
}

static struct page *maybe_pte_to_page(pte_t pte)
{
	unsigned long pfn = pte_pfn(pte);
	struct page *page;

	if (unlikely(!pfn_valid(pfn)))
		return NULL;
	page = pfn_to_page(pfn);
	if (PageReserved(page))
		return NULL;
	return page;
}

/* Server-style MMU handles coherency when hashing if HW exec permission
 * is supposed per page (currently 64-bit only). If not, then, we always
 * flush the cache for valid PTEs in set_pte. Embedded CPU without HW exec
 * support falls into the same category.
 */
static pte_t set_pte_filter(pte_t pte)
{
	pte = __pte(pte_val(pte) & ~H_PAGE_HPTEFLAGS);
	if (pte_looks_normal(pte) && !(cpu_has_feature(CPU_FTR_COHERENT_ICACHE) ||
				       cpu_has_feature(CPU_FTR_NOEXECUTE))) {
		struct page *pg = maybe_pte_to_page(pte);
		if (!pg)
			return pte;
		if (!test_bit(PG_arch_1, &pg->flags)) {
			flush_dcache_icache_page(pg);
			set_bit(PG_arch_1, &pg->flags);
		}
	}
	return pte;
}

/*
 * set_pte stores a linux PTE into the linux page table.
 */
void set_pte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
		pte_t pte)
{
	/*
	 * When handling numa faults, we already have the pte marked
	 * _PAGE_PRESENT, but we can be sure that it is not in hpte.
	 * Hence we can use set_pte_at for them.
	 */
	VM_WARN_ON((pte_val(*ptep) & (H_PAGE_PRESENT | H_PAGE_USER)) ==
		   (H_PAGE_PRESENT | H_PAGE_USER));

	/*
	 * Add the pte bit when tryint set a pte
	 */
	pte = __pte(pte_val(pte) | H_PAGE_PTE);

	/* Note: mm->context.id might not yet have been assigned as
	 * this context might not have been activated yet when this
	 * is called.
	 */
	pte = set_pte_filter(pte);

	/* Perform the setting of the PTE */
	__set_pte_at(mm, addr, ptep, pte, 0);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/*
 * This is called when relaxing access to a hugepage. It's also called in the page
 * fault path when we don't hit any of the major fault cases, ie, a minor
 * update of _PAGE_ACCESSED, _PAGE_DIRTY, etc... The generic code will have
 * handled those two for us, we additionally deal with missing execute
 * permission here on some processors
 */
int pmdp_set_access_flags(struct vm_area_struct *vma, unsigned long address,
			  pmd_t *pmdp, pmd_t entry, int dirty)
{
	int changed;
#ifdef CONFIG_DEBUG_VM
	WARN_ON(!pmd_trans_huge(*pmdp));
	assert_spin_locked(&vma->vm_mm->page_table_lock);
#endif
	changed = !pmd_same(*(pmdp), entry);
	if (changed) {
		__ptep_set_access_flags(pmdp_ptep(pmdp), pmd_pte(entry));
		/*
		 * Since we are not supporting SW TLB systems, we don't
		 * have any thing similar to flush_tlb_page_nohash()
		 */
	}
	return changed;
}

unsigned long pmd_hugepage_update(struct mm_struct *mm, unsigned long addr,
				  pmd_t *pmdp, unsigned long clr,
				  unsigned long set)
{

	unsigned long old, tmp;

#ifdef CONFIG_DEBUG_VM
	WARN_ON(!pmd_trans_huge(*pmdp));
	assert_spin_locked(&mm->page_table_lock);
#endif

#ifdef PTE_ATOMIC_UPDATES
	__asm__ __volatile__(
	"1:	ldarx	%0,0,%3\n\
		andi.	%1,%0,%6\n\
		bne-	1b \n\
		andc	%1,%0,%4 \n\
		or	%1,%1,%7\n\
		stdcx.	%1,0,%3 \n\
		bne-	1b"
	: "=&r" (old), "=&r" (tmp), "=m" (*pmdp)
	: "r" (pmdp), "r" (clr), "m" (*pmdp), "i" (H_PAGE_BUSY), "r" (set)
	: "cc" );
#else
	old = pmd_val(*pmdp);
	*pmdp = __pmd((old & ~clr) | set);
#endif
	trace_hugepage_update(addr, old, clr, set);
	if (old & H_PAGE_HASHPTE)
		hpte_do_hugepage_flush(mm, addr, pmdp, old);
	return old;
}

pmd_t pmdp_collapse_flush(struct vm_area_struct *vma, unsigned long address,
			  pmd_t *pmdp)
{
	pmd_t pmd;

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
	VM_BUG_ON(pmd_trans_huge(*pmdp));

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
	/*
	 * Now invalidate the hpte entries in the range
	 * covered by pmd. This make sure we take a
	 * fault and will find the pmd as none, which will
	 * result in a major fault which takes mmap_sem and
	 * hence wait for collapse to complete. Without this
	 * the __collapse_huge_page_copy can result in copying
	 * the old content.
	 */
	flush_tlb_pmd_range(vma->vm_mm, &pmd, address);
	return pmd;
}

int pmdp_test_and_clear_young(struct vm_area_struct *vma,
			      unsigned long address, pmd_t *pmdp)
{
	return __pmdp_test_and_clear_young(vma->vm_mm, address, pmdp);
}

/*
 * We currently remove entries from the hashtable regardless of whether
 * the entry was young or dirty. The generic routines only flush if the
 * entry was young or dirty which is not good enough.
 *
 * We should be more intelligent about this but for the moment we override
 * these functions and force a tlb flush unconditionally
 */
int pmdp_clear_flush_young(struct vm_area_struct *vma,
				  unsigned long address, pmd_t *pmdp)
{
	return __pmdp_test_and_clear_young(vma->vm_mm, address, pmdp);
}

/*
 * We mark the pmd splitting and invalidate all the hpte
 * entries for this hugepage.
 */
void pmdp_splitting_flush(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp)
{
	unsigned long old, tmp;

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);

#ifdef CONFIG_DEBUG_VM
	WARN_ON(!pmd_trans_huge(*pmdp));
	assert_spin_locked(&vma->vm_mm->page_table_lock);
#endif

#ifdef PTE_ATOMIC_UPDATES

	__asm__ __volatile__(
	"1:	ldarx	%0,0,%3\n\
		andi.	%1,%0,%6\n\
		bne-	1b \n\
		oris	%1,%0,%4@h \n\
		stdcx.	%1,0,%3 \n\
		bne-	1b"
	: "=&r" (old), "=&r" (tmp), "=m" (*pmdp)
	: "r" (pmdp), "i" (H_PAGE_SPLITTING), "m" (*pmdp), "i" (H_PAGE_BUSY)
	: "cc" );
#else
	old = pmd_val(*pmdp);
	*pmdp = __pmd(old | H_PAGE_SPLITTING);
#endif
	/*
	 * If we didn't had the splitting flag set, go and flush the
	 * HPTE entries.
	 */
	trace_hugepage_splitting(address, old);
	if (!(old & H_PAGE_SPLITTING)) {
		/* We need to flush the hpte */
		if (old & H_PAGE_HASHPTE)
			hpte_do_hugepage_flush(vma->vm_mm, address, pmdp, old);
	}
	/*
	 * This ensures that generic code that rely on IRQ disabling
	 * to prevent a parallel THP split work as expected.
	 */
	kick_all_cpus_sync();
}

/*
 * We want to put the pgtable in pmd and use pgtable for tracking
 * the base page size hptes
 */
void pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				pgtable_t pgtable)
{
	pgtable_t *pgtable_slot;
	assert_spin_locked(&mm->page_table_lock);
	/*
	 * we store the pgtable in the second half of PMD
	 */
	pgtable_slot = (pgtable_t *)pmdp + H_PTRS_PER_PMD;
	*pgtable_slot = pgtable;
	/*
	 * expose the deposited pgtable to other cpus.
	 * before we set the hugepage PTE at pmd level
	 * hash fault code looks at the deposted pgtable
	 * to store hash index values.
	 */
	smp_wmb();
}

pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp)
{
	pgtable_t pgtable;
	pgtable_t *pgtable_slot;

	assert_spin_locked(&mm->page_table_lock);
	pgtable_slot = (pgtable_t *)pmdp + H_PTRS_PER_PMD;
	pgtable = *pgtable_slot;
	/*
	 * Once we withdraw, mark the entry NULL.
	 */
	*pgtable_slot = NULL;
	/*
	 * We store HPTE information in the deposited PTE fragment.
	 * zero out the content on withdraw.
	 */
	memset(pgtable, 0, H_PTE_FRAG_SIZE);
	return pgtable;
}

/*
 * set a new huge pmd. We should not be called for updating
 * an existing pmd entry. That should go via pmd_hugepage_update.
 */
void set_pmd_at(struct mm_struct *mm, unsigned long addr,
		pmd_t *pmdp, pmd_t pmd)
{
#ifdef CONFIG_DEBUG_VM
	WARN_ON((pmd_val(*pmdp) & (H_PAGE_PRESENT | H_PAGE_USER)) ==
		(H_PAGE_PRESENT | H_PAGE_USER));
	assert_spin_locked(&mm->page_table_lock);
	WARN_ON(!pmd_trans_huge(pmd));
#endif
	trace_hugepage_set_pmd(addr, pmd_val(pmd));
	return set_pte_at(mm, addr, pmdp_ptep(pmdp), pmd_pte(pmd));
}

void pmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
		     pmd_t *pmdp)
{
	pmd_hugepage_update(vma->vm_mm, address, pmdp, H_PAGE_PRESENT, 0);
}

/*
 * A linux hugepage PMD was changed and the corresponding hash table entries
 * neesd to be flushed.
 */
void hpte_do_hugepage_flush(struct mm_struct *mm, unsigned long addr,
			    pmd_t *pmdp, unsigned long old_pmd)
{
	int ssize;
	unsigned int psize;
	unsigned long vsid;
	unsigned long flags = 0;
	const struct cpumask *tmp;

	/* get the base page size,vsid and segment size */
#ifdef CONFIG_DEBUG_VM
	psize = get_slice_psize(mm, addr);
	BUG_ON(psize == MMU_PAGE_16M);
#endif
	if (old_pmd & H_PAGE_COMBO)
		psize = MMU_PAGE_4K;
	else
		psize = MMU_PAGE_64K;

	if (!is_kernel_addr(addr)) {
		ssize = user_segment_size(addr);
		vsid = get_vsid(mm->context.id, addr, ssize);
		WARN_ON(vsid == 0);
	} else {
		vsid = get_kernel_vsid(addr, mmu_kernel_ssize);
		ssize = mmu_kernel_ssize;
	}

	tmp = cpumask_of(smp_processor_id());
	if (cpumask_equal(mm_cpumask(mm), tmp))
		flags |= HPTE_LOCAL_UPDATE;

	return flush_hash_hugepage(vsid, addr, pmdp, psize, ssize, flags);
}

static pmd_t pmd_set_protbits(pmd_t pmd, pgprot_t pgprot)
{
	return __pmd(pmd_val(pmd) | pgprot_val(pgprot));
}

pmd_t pfn_pmd(unsigned long pfn, pgprot_t pgprot)
{
	unsigned long pmdv;

	pmdv = pfn << H_PTE_RPN_SHIFT;
	return pmd_set_protbits(__pmd(pmdv), pgprot);
}

pmd_t mk_pmd(struct page *page, pgprot_t pgprot)
{
	return pfn_pmd(page_to_pfn(page), pgprot);
}

pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{
	unsigned long pmdv;

	pmdv = pmd_val(pmd);
	pmdv &= H_HPAGE_CHG_MASK;
	return pmd_set_protbits(__pmd(pmdv), newprot);
}

/*
 * This is called at the end of handling a user page fault, when the
 * fault has been handled by updating a HUGE PMD entry in the linux page tables.
 * We use it to preload an HPTE into the hash table corresponding to
 * the updated linux HUGE PMD entry.
 */
void update_mmu_cache_pmd(struct vm_area_struct *vma, unsigned long addr,
			  pmd_t *pmd)
{
	return;
}

pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
			      unsigned long addr, pmd_t *pmdp)
{
	pmd_t old_pmd;
	pgtable_t pgtable;
	unsigned long old;
	pgtable_t *pgtable_slot;

	old = pmd_hugepage_update(mm, addr, pmdp, ~0UL, 0);
	old_pmd = __pmd(old);
	/*
	 * We have pmd == none and we are holding page_table_lock.
	 * So we can safely go and clear the pgtable hash
	 * index info.
	 */
	pgtable_slot = (pgtable_t *)pmdp + H_PTRS_PER_PMD;
	pgtable = *pgtable_slot;
	/*
	 * Let's zero out old valid and hash index details
	 * hash fault look at them.
	 */
	memset(pgtable, 0, H_PTE_FRAG_SIZE);
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

int has_transparent_hugepage(void)
{

	BUILD_BUG_ON_MSG((H_PMD_SHIFT - PAGE_SHIFT) >= MAX_ORDER,
		"hugepages can't be allocated by the buddy allocator");

	if (!mmu_has_feature(MMU_FTR_16M_PAGE))
		return 0;
	/*
	 * We support THP only if PMD_SIZE is 16MB.
	 */
	if (mmu_psize_defs[MMU_PAGE_16M].shift != H_PMD_SHIFT)
		return 0;
	/*
	 * We need to make sure that we support 16MB hugepage in a segement
	 * with base page size 64K or 4K. We only enable THP with a PAGE_SIZE
	 * of 64K.
	 */
	/*
	 * If we have 64K HPTE, we will be using that by default
	 */
	if (mmu_psize_defs[MMU_PAGE_64K].shift &&
	    (mmu_psize_defs[MMU_PAGE_64K].penc[MMU_PAGE_16M] == -1))
		return 0;
	/*
	 * Ok we only have 4K HPTE
	 */
	if (mmu_psize_defs[MMU_PAGE_4K].penc[MMU_PAGE_16M] == -1)
		return 0;

	return 1;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
