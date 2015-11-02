#ifndef _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_4K_H
#define _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_4K_H

static inline void hlpmd_populate(struct mm_struct *mm, pmd_t *pmd,
				pgtable_t pte_page)
{
	pmd_set(pmd, (unsigned long)page_address(pte_page));
}

static inline pgtable_t hlpmd_pgtable(pmd_t pmd)
{
	return pmd_page(pmd);
}

static inline pte_t *hlpte_alloc_one_kernel(struct mm_struct *mm,
					    unsigned long address)
{
	return (pte_t *)__get_free_page(GFP_KERNEL | __GFP_REPEAT | __GFP_ZERO);
}

static inline pgtable_t hlpte_alloc_one(struct mm_struct *mm,
					unsigned long address)
{
	struct page *page;
	pte_t *pte;

	pte = hlpte_alloc_one_kernel(mm, address);
	if (!pte)
		return NULL;
	page = virt_to_page(pte);
	if (!pgtable_page_ctor(page)) {
		__free_page(page);
		return NULL;
	}
	return page;
}

static inline void hlpte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	free_page((unsigned long)pte);
}

static inline void hlpte_free(struct mm_struct *mm, pgtable_t ptepage)
{
	pgtable_page_dtor(ptepage);
	__free_page(ptepage);
}

static inline void pgtable_free(void *table, unsigned index_size)
{
	if (!index_size)
		free_page((unsigned long)table);
	else {
		BUG_ON(index_size > MAX_PGTABLE_INDEX_SIZE);
		kmem_cache_free(PGT_CACHE(index_size), table);
	}
}

#ifdef CONFIG_SMP
static inline void pgtable_free_tlb(struct mmu_gather *tlb,
				      void *table, int shift)
{
	unsigned long pgf = (unsigned long)table;
	BUG_ON(shift > MAX_PGTABLE_INDEX_SIZE);
	pgf |= shift;
	tlb_remove_table(tlb, (void *)pgf);
}

static inline void __tlb_remove_table(void *_table)
{
	void *table = (void *)((unsigned long)_table & ~MAX_PGTABLE_INDEX_SIZE);
	unsigned shift = (unsigned long)_table & MAX_PGTABLE_INDEX_SIZE;

	pgtable_free(table, shift);
}
#else /* !CONFIG_SMP */
static inline void pgtable_free_tlb(struct mmu_gather *tlb,
				      void *table, int shift)
{
	pgtable_free(table, shift);
}
#endif /* CONFIG_SMP */

static inline void __hlpte_free_tlb(struct mmu_gather *tlb, pgtable_t table,
				    unsigned long address)
{
	tlb_flush_pgtable(tlb, address);
	pgtable_page_dtor(table);
	pgtable_free_tlb(tlb, page_address(table), 0);
}

#endif /* _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_4K_H */
