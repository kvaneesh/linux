#ifndef _ASM_POWERPC_BOOK3S_64_HASH_64K_H
#define _ASM_POWERPC_BOOK3S_64_HASH_64K_H

#define H_PTE_INDEX_SIZE  8
#define H_PMD_INDEX_SIZE  5
#define H_PUD_INDEX_SIZE  5
#define H_PGD_INDEX_SIZE  12

#define H_PTRS_PER_PTE	(1 << H_PTE_INDEX_SIZE)
#define H_PTRS_PER_PMD	(1 << H_PMD_INDEX_SIZE)
#define H_PTRS_PER_PUD	(1 << H_PUD_INDEX_SIZE)
#define H_PTRS_PER_PGD	(1 << H_PGD_INDEX_SIZE)

/* With 4k base page size, hugepage PTEs go at the PMD level */
#define MIN_HUGEPTE_SHIFT	PAGE_SHIFT

/* PMD_SHIFT determines what a second-level page table entry can map */
#define H_PMD_SHIFT	(PAGE_SHIFT + H_PTE_INDEX_SIZE)
#define H_PMD_SIZE	(1UL << H_PMD_SHIFT)
#define H_PMD_MASK	(~(H_PMD_SIZE-1))

/* PUD_SHIFT determines what a third-level page table entry can map */
#define H_PUD_SHIFT	(H_PMD_SHIFT + H_PMD_INDEX_SIZE)
#define H_PUD_SIZE	(1UL << H_PUD_SHIFT)
#define H_PUD_MASK	(~(H_PUD_SIZE-1))

/* PGDIR_SHIFT determines what a third-level page table entry can map */
#define H_PGDIR_SHIFT	(H_PUD_SHIFT + H_PUD_INDEX_SIZE)
#define H_PGDIR_SIZE	(1UL << H_PGDIR_SHIFT)
#define H_PGDIR_MASK	(~(H_PGDIR_SIZE-1))

#define H_PAGE_COMBO	0x00020000 /* this is a combo 4k page */
#define H_PAGE_4K_PFN	0x00040000 /* PFN is for a single 4k page */
/*
 * Used to track subpage group valid if _PAGE_COMBO is set
 * This overloads _PAGE_F_GIX and _PAGE_F_SECOND
 */
#define H_PAGE_COMBO_VALID	(H_PAGE_F_GIX | H_PAGE_F_SECOND)

/* PTE flags to conserve for HPTE identification */
#define H_PAGE_HPTEFLAGS (H_PAGE_BUSY | H_PAGE_F_SECOND | \
			  H_PAGE_F_GIX | H_PAGE_HASHPTE | H_PAGE_COMBO)

/* Shift to put page number into pte.
 *
 * That gives us a max RPN of 34 bits, which means a max of 50 bits
 * of addressable physical space, or 46 bits for the special 4k PFNs.
 */
#define H_PTE_RPN_SHIFT	(30)
/*
 * we support 16 fragments per PTE page of 64K size.
 */
#define H_PTE_FRAG_NR	16
/*
 * We use a 2K PTE page fragment and another 2K for storing
 * real_pte_t hash index
 */
#define H_PTE_FRAG_SIZE_SHIFT  12
#define H_PTE_FRAG_SIZE (1UL << H_PTE_FRAG_SIZE_SHIFT)
/*
 * Bits to mask out from a PMD to get to the PTE page
 * PMDs point to PTE table fragments which are PTE_FRAG_SIZE aligned.
 */
#define H_PMD_MASKED_BITS		(H_PTE_FRAG_SIZE - 1)
/* Bits to mask out from a PGD/PUD to get to the PMD page */
#define H_PUD_MASKED_BITS		0x1ff
/* FIXME!! check this */
#define H_PGD_MASKED_BITS		0

#ifndef __ASSEMBLY__

/*
 * With 64K pages on hash table, we have a special PTE format that
 * uses a second "half" of the page table to encode sub-page information
 * in order to deal with 64K made of 4K HW pages. Thus we override the
 * generic accessors and iterators here
 */
#define __real_pte __real_pte
static inline real_pte_t __real_pte(pte_t pte, pte_t *ptep)
{
	real_pte_t rpte;
	unsigned long *hidxp;

	rpte.pte = pte;
	rpte.hidx = 0;
	if (pte_val(pte) & H_PAGE_COMBO) {
		/*
		 * Make sure we order the hidx load against the _PAGE_COMBO
		 * check. The store side ordering is done in __hash_page_4K
		 */
		smp_rmb();
		hidxp = (unsigned long *)(ptep + H_PTRS_PER_PTE);
		rpte.hidx = *hidxp;
	}
	return rpte;
}

static inline unsigned long __rpte_to_hidx(real_pte_t rpte, unsigned long index)
{
	if ((pte_val(rpte.pte) & H_PAGE_COMBO))
		return (rpte.hidx >> (index<<2)) & 0xf;
	return (pte_val(rpte.pte) >> H_PAGE_F_GIX_SHIFT) & 0xf;
}

#define __rpte_to_pte(r)	((r).pte)
extern bool __rpte_sub_valid(real_pte_t rpte, unsigned long index);
/*
 * Trick: we set __end to va + 64k, which happens works for
 * a 16M page as well as we want only one iteration
 */
#define pte_iterate_hashed_subpages(rpte, psize, vpn, index, shift)	\
	do {								\
		unsigned long __end = vpn + (1UL << (PAGE_SHIFT - VPN_SHIFT));	\
		unsigned __split = (psize == MMU_PAGE_4K ||		\
				    psize == MMU_PAGE_64K_AP);		\
		shift = mmu_psize_defs[psize].shift;			\
		for (index = 0; vpn < __end; index++,			\
			     vpn += (1L << (shift - VPN_SHIFT))) {	\
			if (!__split || __rpte_sub_valid(rpte, index))	\
				do {

#define pte_iterate_hashed_end() } while(0); } } while(0)

#define pte_pagesize_index(mm, addr, pte)	\
	(((pte) & H_PAGE_COMBO)? MMU_PAGE_4K: MMU_PAGE_64K)

#define remap_4k_pfn(vma, addr, pfn, prot)				\
	(WARN_ON(((pfn) >= (1UL << (64 - H_PTE_RPN_SHIFT)))) ? -EINVAL :	\
		remap_pfn_range((vma), (addr), (pfn), PAGE_SIZE,	\
			__pgprot(pgprot_val((prot)) | H_PAGE_4K_PFN)))

#define H_PTE_TABLE_SIZE	H_PTE_FRAG_SIZE
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define H_PMD_TABLE_SIZE	((sizeof(pmd_t) << H_PMD_INDEX_SIZE) + (sizeof(unsigned long) << H_PMD_INDEX_SIZE))
#else
#define H_PMD_TABLE_SIZE	(sizeof(pmd_t) <<H_PMD_INDEX_SIZE)
#endif
#define H_PUD_TABLE_SIZE	(sizeof(pud_t) << H_PUD_INDEX_SIZE)
#define H_PGD_TABLE_SIZE	(sizeof(pgd_t) << H_PGD_INDEX_SIZE)

#ifdef CONFIG_HUGETLB_PAGE
/*
 * We have PGD_INDEX_SIZ = 12 and PTE_INDEX_SIZE = 8, so that we can have
 * 16GB hugepage pte in PGD and 16MB hugepage pte at PMD;
 *
 * Defined in such a way that we can optimize away code block at build time
 * if CONFIG_HUGETLB_PAGE=n.
 */
static inline int pmd_huge(pmd_t pmd)
{
	/*
	 * leaf pte for huge page
	 */
	return !!(pmd_val(pmd) & H_PAGE_PTE);
}

static inline int pud_huge(pud_t pud)
{
	/*
	 * leaf pte for huge page
	 */
	return !!(pud_val(pud) & H_PAGE_PTE);
}

static inline int pgd_huge(pgd_t pgd)
{
	/*
	 * leaf pte for huge page
	 */
	return !!(pgd_val(pgd) & H_PAGE_PTE);
}
#define pgd_huge pgd_huge

#ifdef CONFIG_DEBUG_VM
extern int hugepd_ok(hugepd_t hpd);
#define is_hugepd(hpd)               (hugepd_ok(hpd))
#else
/*
 * With 64k page size, we have hugepage ptes in the pgd and pmd entries. We don't
 * need to setup hugepage directory for them. Our pte and page directory format
 * enable us to have this enabled.
 */
static inline int hugepd_ok(hugepd_t hpd)
{
	return 0;
}
#define is_hugepd(pdep)			0
#endif /* CONFIG_DEBUG_VM */

#endif /* CONFIG_HUGETLB_PAGE */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE

extern pmd_t pfn_hlpmd(unsigned long pfn, pgprot_t pgprot);
extern pmd_t mk_hlpmd(struct page *page, pgprot_t pgprot);
extern pmd_t hlpmd_modify(pmd_t pmd, pgprot_t newprot);
extern int hl_has_transparent_hugepage(void);
extern void set_hlpmd_at(struct mm_struct *mm, unsigned long addr,
			 pmd_t *pmdp, pmd_t pmd);

extern unsigned long hlpmd_hugepage_update(struct mm_struct *mm,
					   unsigned long addr,
					   pmd_t *pmdp,
					   unsigned long clr,
					   unsigned long set);
static inline char *get_hpte_slot_array(pmd_t *pmdp)
{
	/*
	 * The hpte hindex is stored in the pgtable whose address is in the
	 * second half of the PMD
	 *
	 * Order this load with the test for pmd_trans_huge in the caller
	 */
	smp_rmb();
	return *(char **)(pmdp + H_PTRS_PER_PMD);


}
/*
 * The linux hugepage PMD now include the pmd entries followed by the address
 * to the stashed pgtable_t. The stashed pgtable_t contains the hpte bits.
 * [ 1 bit secondary | 3 bit hidx | 1 bit valid | 000]. We use one byte per
 * each HPTE entry. With 16MB hugepage and 64K HPTE we need 256 entries and
 * with 4K HPTE we need 4096 entries. Both will fit in a 4K pgtable_t.
 *
 * The last three bits are intentionally left to zero. This memory location
 * are also used as normal page PTE pointers. So if we have any pointers
 * left around while we collapse a hugepage, we need to make sure
 * _PAGE_PRESENT bit of that is zero when we look at them
 */
static inline unsigned int hpte_valid(unsigned char *hpte_slot_array, int index)
{
	return (hpte_slot_array[index] >> 3) & 0x1;
}

static inline unsigned int hpte_hash_index(unsigned char *hpte_slot_array,
					   int index)
{
	return hpte_slot_array[index] >> 4;
}

static inline void mark_hpte_slot_valid(unsigned char *hpte_slot_array,
					unsigned int index, unsigned int hidx)
{
	hpte_slot_array[index] = hidx << 4 | 0x1 << 3;
}

/*
 *
 * For core kernel code by design pmd_trans_huge is never run on any hugetlbfs
 * page. The hugetlbfs page table walking and mangling paths are totally
 * separated form the core VM paths and they're differentiated by
 *  VM_HUGETLB being set on vm_flags well before any pmd_trans_huge could run.
 *
 * pmd_trans_huge() is defined as false at build time if
 * CONFIG_TRANSPARENT_HUGEPAGE=n to optimize away code blocks at build
 * time in such case.
 *
 * For ppc64 we need to differntiate from explicit hugepages from THP, because
 * for THP we also track the subpage details at the pmd level. We don't do
 * that for explicit huge pages.
 *
 */
static inline int hlpmd_trans_huge(pmd_t pmd)
{
	return !!((pmd_val(pmd) & (H_PAGE_PTE | H_PAGE_THP_HUGE)) ==
		  (H_PAGE_PTE | H_PAGE_THP_HUGE));
}

static inline int hlpmd_trans_splitting(pmd_t pmd)
{
	if (hlpmd_trans_huge(pmd))
		return pmd_val(pmd) & H_PAGE_SPLITTING;
	return 0;
}

static inline int hlpmd_large(pmd_t pmd)
{
	return !!(pmd_val(pmd) & H_PAGE_PTE);
}

static inline pmd_t hlpmd_mknotpresent(pmd_t pmd)
{
	return __pmd(pmd_val(pmd) & ~H_PAGE_PRESENT);
}

static inline pmd_t hlpmd_mksplitting(pmd_t pmd)
{
	return __pmd(pmd_val(pmd) | H_PAGE_SPLITTING);
}

static inline pmd_t hlpmd_mkhuge(pmd_t pmd)
{
	return __pmd(pmd_val(pmd) | (H_PAGE_PTE | H_PAGE_THP_HUGE));
}

static inline int hlpmd_same(pmd_t pmd_a, pmd_t pmd_b)
{
	return (((pmd_val(pmd_a) ^ pmd_val(pmd_b)) & ~H_PAGE_HPTEFLAGS) == 0);
}

static inline int __hlpmdp_test_and_clear_young(struct mm_struct *mm,
					      unsigned long addr, pmd_t *pmdp)
{
	unsigned long old;

	if ((pmd_val(*pmdp) & (H_PAGE_ACCESSED | H_PAGE_HASHPTE)) == 0)
		return 0;
	old = hlpmd_hugepage_update(mm, addr, pmdp, H_PAGE_ACCESSED, 0);
	return ((old & H_PAGE_ACCESSED) != 0);
}

static inline void hlpmdp_set_wrprotect(struct mm_struct *mm, unsigned long addr,
				      pmd_t *pmdp)
{

	if ((pmd_val(*pmdp) & H_PAGE_RW) == 0)
		return;

	hlpmd_hugepage_update(mm, addr, pmdp, H_PAGE_RW, 0);
}

#endif /*  CONFIG_TRANSPARENT_HUGEPAGE */

#endif	/* __ASSEMBLY__ */

#endif /* _ASM_POWERPC_BOOK3S_64_HASH_64K_H */
