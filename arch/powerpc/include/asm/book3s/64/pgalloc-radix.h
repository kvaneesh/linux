#ifndef _ASM_POWERPC_PGALLOC_radix_H
#define _ASM_POWERPC_PGALLOC_radix_H

#include <linux/slab.h>
#define PGALLOC_GFP GFP_KERNEL | __GFP_NOTRACK | __GFP_REPEAT | __GFP_ZERO

static inline pgd_t *rpgd_alloc(struct mm_struct *mm)
{
#ifdef CONFIG_PPC_64K_PAGES
	return (pgd_t *)__get_free_page(PGALLOC_GFP);
#else
	struct page *page;
	page = alloc_pages(PGALLOC_GFP, 4);
	if (!page)
		return NULL;
	return (pgd_t *) page_address(page);
#endif
}

static inline void rpgd_free(struct mm_struct *mm, pgd_t *pgd)
{
#ifdef CONFIG_PPC_64K_PAGES
	free_page((unsigned long)pgd);
#else
	free_pages((unsigned long)pgd, 4);
#endif
}

static inline void rpgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	*pgd = __pgd(__pa(pud) | RPGD_VAL_BITS);
}

static inline pud_t *rpud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return kmem_cache_alloc(PGT_CACHE(RPUD_INDEX_SIZE),
				GFP_KERNEL|__GFP_REPEAT);
}

static inline void rpud_free(struct mm_struct *mm, pud_t *pud)
{
	kmem_cache_free(PGT_CACHE(RPUD_INDEX_SIZE), pud);
}

static inline void rpud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	*pud = __pud(__pa(pmd) | RPUD_VAL_BITS);
}

static inline void __rpud_free_tlb(struct mmu_gather *tlb, pud_t *pud,
				  unsigned long address)
{
	pgtable_free_tlb(tlb, pud, RPUD_INDEX_SIZE);
}

static inline pmd_t *rpmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return kmem_cache_alloc(PGT_CACHE(RPMD_CACHE_INDEX),
				GFP_KERNEL|__GFP_REPEAT);
}

static inline void rpmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	kmem_cache_free(PGT_CACHE(RPMD_CACHE_INDEX), pmd);
}

static inline void rpmd_populate_kernel(struct mm_struct *mm,
				       pmd_t *pmdp, pte_t *pte)
{
	/* strict mm type need fixes */
	*pmdp = __pmd(__pa(pte) | RPMD_VAL_BITS);
}


static inline void rpmd_populate(struct mm_struct *mm, pmd_t *pmdp,
				pgtable_t pte)
{
	*pmdp = __pmd(__pa(pte) | RPMD_VAL_BITS);
}

static inline void __rpmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd,
				  unsigned long address)
{
	pgtable_free_tlb(tlb, pmd, RPMD_CACHE_INDEX);
}

/*
 * We may have to use fragments here. But for now just deal
 * with one page.
 */
static inline pte_t *rpte_alloc_one_kernel(struct mm_struct *mm,
					  unsigned long address)
{
	return (pte_t *)__get_free_page(PGALLOC_GFP);
}

extern pgtable_t rpte_alloc_one(struct mm_struct *mm, unsigned long address);

static inline void rpte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	BUG_ON((unsigned long)pte & (PAGE_SIZE-1));
	free_page((unsigned long)pte);
}

static inline void rpte_free(struct mm_struct *mm, pgtable_t pte)
{
	struct page *page = virt_to_page(pte);
	pgtable_page_dtor(page);
	__free_page(page);
}

static inline void __rpte_free_tlb(struct mmu_gather *tlb, pgtable_t pte,
				  unsigned long address)
{
	tlb_flush_pgtable(tlb, address);
	pgtable_free_tlb(tlb, pte, 0);
}

#endif
