#ifndef _ASM_POWERPC_BOOK3S_64_PGALLOC_H
#define _ASM_POWERPC_BOOK3S_64_PGALLOC_H
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>

/*
 * Functions that deal with pagetables that could be at any level of
 * the table need to be passed an "index_size" so they know how to
 * handle allocation.  For PTE pages (which are linked to a struct
 * page for now, and drawn from the main get_free_pages() pool), the
 * allocation size will be (2^index_size * sizeof(pointer)) and
 * allocations are drawn from the kmem_cache in PGT_CACHE(index_size).
 *
 * The maximum index size needs to be big enough to allow any
 * pagetable sizes we need, but small enough to fit in the low bits of
 * any page table pointer.  In other words all pagetables, even tiny
 * ones, must be aligned to allow at least enough low 0 bits to
 * contain this value.  This value is also used as a mask, so it must
 * be one less than a power of two.
 */
#define MAX_PGTABLE_INDEX_SIZE	0xf

extern struct kmem_cache *pgtable_cache[];
#define PGT_CACHE(shift) ({				\
			BUG_ON(!(shift));		\
			pgtable_cache[(shift) - 1];	\
		})

#include <asm/book3s/64/pgalloc-hash.h>
#include <asm/book3s/64/pgalloc-radix.h>

struct vmemmap_backing {
	struct vmemmap_backing *list;
	unsigned long phys;
	unsigned long virt_addr;
};
extern struct vmemmap_backing *vmemmap_list;
extern void __tlb_remove_table(void *table);

static inline void check_pgt_cache(void)
{

}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	if (radix_enabled())
		return rpgd_populate(mm, pgd, pud);
	return hlpgd_populate(mm, pgd, pud);
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	if (radix_enabled())
		return rpud_populate(mm, pud, pmd);
	return hlpud_populate(mm, pud, pmd);
}

static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd,
				       pte_t *pte)
{
	if (radix_enabled())
		return rpmd_populate_kernel(mm, pmd, pte);
	return hlpmd_populate_kernel(mm, pmd, pte);
}

#ifdef CONFIG_HUGETLB_PAGE
static inline void hugetlb_free_pgd_range(struct mmu_gather *tlb, unsigned long addr,
					  unsigned long end, unsigned long floor,
					  unsigned long ceiling)
{
	return hugetlb_free_hlpgd_range(tlb, addr, end, floor, ceiling);
}
#endif

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	if (radix_enabled())
		return rpgd_alloc(mm);
	return hlpgd_alloc(mm);
}

static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (radix_enabled())
		return rpgd_free(mm, pgd);
	return hlpgd_free(mm, pgd);
}

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	if (radix_enabled())
		return rpud_alloc_one(mm, addr);
	return hlpud_alloc_one(mm, addr);
}

static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	if (radix_enabled())
		return rpud_free(mm, pud);
	return hlpud_free(mm, pud);
}

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	if (radix_enabled())
		return rpmd_alloc_one(mm, addr);
	return hlpmd_alloc_one(mm, addr);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	if (radix_enabled())
		return rpmd_free(mm, pmd);
	return hlpmd_free(mm, pmd);
}

static inline void __pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd,
				  unsigned long address)
{
	if (radix_enabled())
		return __rpmd_free_tlb(tlb, pmd, address);
	return __hlpmd_free_tlb(tlb, pmd, address);
}

static inline void __pud_free_tlb(struct mmu_gather *tlb, pud_t *pud,
				  unsigned long address)
{
	if (radix_enabled())
		return __rpud_free_tlb(tlb, pud, address);
	return __hlpud_free_tlb(tlb, pud, address);
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd,
				pgtable_t pte_page)
{
	if (radix_enabled())
		return rpmd_populate(mm, pmd, pte_page);
	return hlpmd_populate(mm, pmd, pte_page);
}

static inline pgtable_t pmd_pgtable(pmd_t pmd)
{
	if (radix_enabled())
		return (pgtable_t)rpmd_page_vaddr(pmd);
	return hlpmd_pgtable(pmd);
}

static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm,
					  unsigned long address)
{
	if (radix_enabled())
		return rpte_alloc_one_kernel(mm, address);
	return hlpte_alloc_one_kernel(mm, address);
}

static inline pgtable_t pte_alloc_one(struct mm_struct *mm,
				      unsigned long address)
{
	if (radix_enabled())
		return rpte_alloc_one(mm, address);
	return hlpte_alloc_one(mm, address);
}

static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	if (radix_enabled())
		return rpte_free_kernel(mm, pte);
	return hlpte_free_kernel(mm, pte);
}

static inline void pte_free(struct mm_struct *mm, pgtable_t ptepage)
{
	if (radix_enabled())
		return rpte_free(mm, ptepage);
	return hlpte_free(mm, ptepage);
}

static inline void __pte_free_tlb(struct mmu_gather *tlb, pgtable_t table,
				  unsigned long address)
{
	if (radix_enabled())
		return __rpte_free_tlb(tlb, table, address);
	return __hlpte_free_tlb(tlb, table, address);
}

#endif /* __ASM_POWERPC_BOOK3S_64_PGALLOC_H */
