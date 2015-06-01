#ifndef _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_64K_H
#define _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_64K_H

extern pte_t *page_table_alloc(struct mm_struct *, unsigned long, int);
extern void page_table_free(struct mm_struct *, unsigned long *, int);
extern void pgtable_free_tlb(struct mmu_gather *tlb, void *table, int shift);
#ifdef CONFIG_SMP
extern void __tlb_remove_table(void *_table);
#endif

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd,
				pgtable_t pte_page)
{
	pmd_set(pmd, (unsigned long)pte_page);
}

static inline pgtable_t pmd_pgtable(pmd_t pmd)
{
	return (pgtable_t)pmd_page_vaddr(pmd);
}

static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm,
					  unsigned long address)
{
	return (pte_t *)page_table_alloc(mm, address, 1);
}

static inline pgtable_t pte_alloc_one(struct mm_struct *mm,
					unsigned long address)
{
	return (pgtable_t)page_table_alloc(mm, address, 0);
}

static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	page_table_free(mm, (unsigned long *)pte, 1);
}

static inline void pte_free(struct mm_struct *mm, pgtable_t ptepage)
{
	page_table_free(mm, (unsigned long *)ptepage, 0);
}

static inline void __pte_free_tlb(struct mmu_gather *tlb, pgtable_t table,
				  unsigned long address)
{
	tlb_flush_pgtable(tlb, address);
	pgtable_free_tlb(tlb, table, 0);
}

#endif /* _ASM_POWERPC_BOOK3S_64_PGALLOC_HASH_64K_H */
