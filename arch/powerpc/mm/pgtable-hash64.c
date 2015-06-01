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
