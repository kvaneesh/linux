#ifndef _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_H
#define _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_H

/*
 * FIXME!!
 * Between 4K and 64K pages, we differ in what is stored in pmd. ie.
 * typedef pte_t *pgtable_t; -> 64K
 * typedef struct page *pgtable_t; -> 4k
 */
#ifdef CONFIG_PPC_64K_PAGES
#include <asm/book3s/64/pgalloc-hash-64k.h>
#else
#include <asm/book3s/64/pgalloc-hash-4k.h>
#endif

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	return kmem_cache_alloc(PGT_CACHE(H_PGD_INDEX_SIZE), GFP_KERNEL);
}

static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	kmem_cache_free(PGT_CACHE(H_PGD_INDEX_SIZE), pgd);
}

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return kmem_cache_alloc(PGT_CACHE(H_PUD_INDEX_SIZE),
				GFP_KERNEL|__GFP_REPEAT);
}

static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	kmem_cache_free(PGT_CACHE(H_PUD_INDEX_SIZE), pud);
}

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return kmem_cache_alloc(PGT_CACHE(H_PMD_CACHE_INDEX),
				GFP_KERNEL|__GFP_REPEAT);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	kmem_cache_free(PGT_CACHE(H_PMD_CACHE_INDEX), pmd);
}

static inline void __pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd,
				unsigned long address)
{
	return pgtable_free_tlb(tlb, pmd, H_PMD_CACHE_INDEX);
}

static inline void __pud_free_tlb(struct mmu_gather *tlb, pud_t *pud,
				unsigned long address)
{
	pgtable_free_tlb(tlb, pud, H_PUD_INDEX_SIZE);
}

extern pte_t *huge_hlpte_alloc(struct mm_struct *mm, unsigned long addr,
			       unsigned long sz);
extern void hugetlb_free_hlpgd_range(struct mmu_gather *tlb, unsigned long addr,
				     unsigned long end, unsigned long floor,
				     unsigned long ceiling);

#endif /* _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_H */
