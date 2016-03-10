#ifndef _ASM_POWERPC_PGTABLE_RADIX_H
#define _ASM_POWERPC_PGTABLE_RADIX_H

#ifndef __ASSEMBLY__
#include <asm/cmpxchg.h>
#endif

#ifdef CONFIG_PPC_64K_PAGES
#include <asm/book3s/64/radix-64k.h>
#else
#include <asm/book3s/64/radix-4k.h>
#endif

/* An empty PTE can still have a R or C writeback */
#define R_PTE_NONE_MASK		(_PAGE_DIRTY | _PAGE_ACCESSED)

/* Bits to set in a RPMD/RPUD/RPGD */
#define R_PMD_VAL_BITS		(0x8000000000000000UL | R_PTE_INDEX_SIZE)
#define R_PUD_VAL_BITS		(0x8000000000000000UL | R_PMD_INDEX_SIZE)
#define R_PGD_VAL_BITS		(0x8000000000000000UL | R_PUD_INDEX_SIZE)

/* Don't have anything in the reserved bits and leaf bits */
#define R_PMD_BAD_BITS		0x60000000000000e0UL
#define R_PUD_BAD_BITS		0x60000000000000e0UL
#define R_PGD_BAD_BITS		0x60000000000000e0UL

/*
 * Size of EA range mapped by our pagetables.
 */
#define R_PGTABLE_EADDR_SIZE (R_PTE_INDEX_SIZE + R_PMD_INDEX_SIZE +	\
			      R_PUD_INDEX_SIZE + R_PGD_INDEX_SIZE + PAGE_SHIFT)
#define R_PGTABLE_RANGE (ASM_CONST(1) << R_PGTABLE_EADDR_SIZE)

#ifndef __ASSEMBLY__
#define R_PTE_TABLE_SIZE	(sizeof(pte_t) << R_PTE_INDEX_SIZE)
#define R_PMD_TABLE_SIZE	(sizeof(pmd_t) << R_PMD_INDEX_SIZE)
#define R_PUD_TABLE_SIZE	(sizeof(pud_t) << R_PUD_INDEX_SIZE)
#define R_PGD_TABLE_SIZE	(sizeof(pgd_t) << R_PGD_INDEX_SIZE)

static inline unsigned long rpte_update(struct mm_struct *mm,
					unsigned long addr,
					pte_t *ptep, unsigned long clr,
					unsigned long set,
					int huge)
{

	pte_t pte;
	unsigned long old_pte, new_pte;

	do {
		pte = READ_ONCE(*ptep);
		old_pte = pte_val(pte);
		new_pte = (old_pte | set) & ~clr;

	} while (cpu_to_be64(old_pte) != __cmpxchg_u64((unsigned long *)ptep,
						       cpu_to_be64(old_pte),
						       cpu_to_be64(new_pte)));
	/* We already do a sync in cmpxchg, is ptesync needed ?*/
	asm volatile("ptesync" : : : "memory");
	/* huge pages use the old page table lock */
	if (!huge)
		assert_pte_locked(mm, addr);

	return old_pte;
}

/*
 * Set the dirty and/or accessed bits atomically in a linux PTE, this
 * function doesn't need to invalidate tlb.
 */
static inline void __rptep_set_access_flags(pte_t *ptep, pte_t entry)
{
	pte_t pte;
	unsigned long old_pte, new_pte;
	unsigned long set = pte_val(entry) & (_PAGE_DIRTY | _PAGE_ACCESSED |
					      _PAGE_RW | _PAGE_EXEC);
	do {
		pte = READ_ONCE(*ptep);
		old_pte = pte_val(pte);
		new_pte = old_pte | set;

	} while (cpu_to_be64(old_pte) != __cmpxchg_u64((unsigned long *)ptep,
						       cpu_to_be64(old_pte),
						       cpu_to_be64(new_pte)));
	/* We already do a sync in cmpxchg, is ptesync needed ?*/
	asm volatile("ptesync" : : : "memory");
}

static inline int rpte_same(pte_t pte_a, pte_t pte_b)
{
	return ((pte_val(pte_a) == pte_val(pte_b)));
}

static inline int rpte_none(pte_t pte)
{
	return (pte_val(pte) & ~R_PTE_NONE_MASK) == 0;
}

static inline void __set_rpte_at(struct mm_struct *mm, unsigned long addr,
				 pte_t *ptep, pte_t pte, int percpu)
{
	*ptep = pte;
	asm volatile("ptesync" : : : "memory");
}

static inline int rpmd_bad(pmd_t pmd)
{
	return !!(pmd_val(pmd) & R_PMD_BAD_BITS);
}

static inline int rpmd_same(pmd_t pmd_a, pmd_t pmd_b)
{
	return ((pmd_val(pmd_a) == pmd_val(pmd_b)));
}

static inline int rpud_bad(pud_t pud)
{
	return !!(pud_val(pud) & R_PUD_BAD_BITS);
}


static inline int rpgd_bad(pgd_t pgd)
{
	return !!(pgd_val(pgd) & R_PGD_BAD_BITS);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE

static inline int rpmd_trans_huge(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _PAGE_PTE);
}

#endif

extern int __meminit rvmemmap_create_mapping(unsigned long start,
					     unsigned long page_size,
					     unsigned long phys);
extern void rvmemmap_remove_mapping(unsigned long start,
				    unsigned long page_size);

extern int map_radix_kernel_page(unsigned long ea, unsigned long pa,
				 pgprot_t flags, unsigned int psz);
#endif /* __ASSEMBLY__ */
#endif
