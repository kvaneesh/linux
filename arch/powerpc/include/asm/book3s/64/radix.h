#ifndef _ASM_POWERPC_PGTABLE_RADIX_H
#define _ASM_POWERPC_PGTABLE_RADIX_H

#ifdef CONFIG_PPC_64K_PAGES
#include <asm/book3s/64/radix-64k.h>
#else
#include <asm/book3s/64/radix-4k.h>
#endif


#define PTRS_PER_RPTE	(1 << RPTE_INDEX_SIZE)

/* RPMD_SHIFT determines what a second-level page table entry can map */
#define RPMD_SHIFT	(PAGE_SHIFT + RPTE_INDEX_SIZE)
#define RPMD_SIZE	(1UL << RPMD_SHIFT)
#define RPMD_MASK	(~(RPMD_SIZE-1))
#define PTRS_PER_RPMD	(1 << RPMD_INDEX_SIZE)

/* RPUD_SHIFT determines what a third-level page table entry can map */
#define RPUD_SHIFT	(RPMD_SHIFT + RPMD_INDEX_SIZE)
#define RPUD_SIZE	(1UL << RPUD_SHIFT)
#define RPUD_MASK	(~(RPUD_SIZE-1))
#define PTRS_PER_RPUD	(1 << RPUD_INDEX_SIZE)

/* RPGDIR_SHIFT determines what a fourth-level page table entry can map */
#define RPGDIR_SHIFT	(RPUD_SHIFT + RPUD_INDEX_SIZE)
#define RPGDIR_SIZE	(1UL << RPGDIR_SHIFT)
#define RPGDIR_MASK	(~(RPGDIR_SIZE-1))
#define PTRS_PER_RPGD	(1 << RPGD_INDEX_SIZE)

/* Bits to mask out from a RPMD to get to the RPTE page */
#define RPMD_MASKED_BITS		0xe0000000000000ffUL
/* Bits to mask out from a RPUD to get to the RPMD page */
#define RPUD_MASKED_BITS		0xe0000000000000ffUL
/* Bits to mask out from a RPGD to get to the RPUD page */
#define RPGD_MASKED_BITS		0xe0000000000000ffUL

/* Bits to set in a RPMD/RPUD/RPGD */
#define RPMD_VAL_BITS		(0x8000000000000000UL | RPTE_INDEX_SIZE)
#define RPUD_VAL_BITS		(0x8000000000000000UL | RPMD_INDEX_SIZE)
#define RPGD_VAL_BITS		(0x8000000000000000UL | RPUD_INDEX_SIZE)

/* Don't have anything in the reserved bits and leaf bits */
#define RPMD_BAD_BITS		0x60000000000000e0UL
#define RPUD_BAD_BITS		0x60000000000000e0UL
#define RPGD_BAD_BITS		0x60000000000000e0UL

/*
 * Size of EA range mapped by our pagetables.
 */
#define RPGTABLE_EADDR_SIZE (RPTE_INDEX_SIZE + RPMD_INDEX_SIZE + \
			     RPUD_INDEX_SIZE + RPGD_INDEX_SIZE + PAGE_SHIFT)
#define RPGTABLE_RANGE (ASM_CONST(1) << RPGTABLE_EADDR_SIZE)

#define RPMD_CACHE_INDEX	RPMD_INDEX_SIZE
/*
 * We support 52 bit address space, Use top bit for kernel
 * virtual mapping. Also make sure kernel fit in the top
 * quadrant.
 */
#define RKERN_VIRT_START ASM_CONST(0xc008000000000000)
#define RKERN_VIRT_SIZE	 ASM_CONST(0x0008000000000000)

/*
 * The vmalloc space starts at the beginning of that region, and
 * occupies a quarter of it on radix config.
 * (we keep a quarter for the virtual memmap)
 */
#define RVMALLOC_START	RKERN_VIRT_START
#define RVMALLOC_SIZE	(RKERN_VIRT_SIZE >> 2)
#define RVMALLOC_END	(RVMALLOC_START + RVMALLOC_SIZE)
/*
 * Defines the address of the vmemap area, in its own region on
 * hash table CPUs.
 */
#define RVMEMMAP_BASE		(RVMALLOC_END)

/* Architected bits */
#define _RPAGE_VALID	PPC_BIT(0)
#define _RPAGE_LEAF	PPC_BIT(1)
#define _RPAGE_SW0	PPC_BIT(2)
#define _RPAGE_SW1	PPC_BIT(52)
#define _RPAGE_SW2	PPC_BIT(53)
#define _RPAGE_SW3	PPC_BIT(54)
#define _RPAGE_ACCESSED	PPC_BIT(55)
#define _RPAGE_DIRTY	PPC_BIT(56)
#define _RPAGE_ATT_SAO	PPC_BIT(59)
#define _RPAGE_EAA_K	PPC_BIT(60)
#define _RPAGE_EAA_R	PPC_BIT(61)
#define _RPAGE_EAA_W	PPC_BIT(62)
#define _RPAGE_EAA_X	PPC_BIT(63)


/* Present must have LEAF set */
#define _RPAGE_PRESENT	(_RPAGE_VALID | _RPAGE_LEAF)

/* Base page size */
#define RPTE_RPN_MASK	PPC_BITMASK(3,52)
/* FIXME!! was page_shift before, so need adjusting other functions */
#define RPTE_RPN_SHIFT  12

/*
 * There is no direct equivalence of the WIMG attributes with the ATT
 * encoding so we play tricks here thanks to carefully chosen ATT encodings
 */
#define _RPAGE_GUARDED		(0x2ull << PPC_BITLSHIFT(59)) /* non-idempotent */
#define _RPAGE_NO_CACHE		(0x3ull << PPC_BITLSHIFT(59)) /* tolerant  */
#define _RPAGE_WRITETHRU	(0x7ull << PPC_BITLSHIFT(59)) /* write through */
#define _RPAGE_COHERENT		0x0 /* Dummy */

/* SAO like server */
#define _RPAGE_SAO		(_RPAGE_ATT_SAO)

/* "Higher level" linux bit combinations */
#define _RPAGE_EXEC		_RPAGE_EAA_X
#define _RPAGE_RW		(_RPAGE_EAA_W)
#define _RPAGE_KERNEL_RO	(_RPAGE_EAA_K | _RPAGE_EAA_R)
/* doesn't a write imply read ? */
#define _RPAGE_KERNEL_RW	(_RPAGE_EAA_K | _RPAGE_EAA_R | _RPAGE_EAA_W)
#define _RPAGE_KERNEL_RWX	(_RPAGE_KERNEL_RW | _RPAGE_EAA_X)
#define _RPAGE_KERNEL_ROX	(_RPAGE_KERNEL_RO | _RPAGE_EAA_X)
/* Do we imply read ? */
#define _RPAGE_USER		(_RPAGE_EAA_R)

#define _RPAGE_SPECIAL		_RPAGE_SW0
#define _RPAGE_SPLITTING	_RPAGE_SW1

/* An empty PTE can still have a R or C writeback */
#define _RPTE_NONE_MASK		(_RPAGE_DIRTY | _RPAGE_ACCESSED)

/* Mask of bits returned by pte_pgprot() */
#define RPAGE_PROT_BITS	(_RPAGE_GUARDED |  _RPAGE_NO_CACHE | \
				 _RPAGE_WRITETHRU | _RPAGE_USER | \
				 _RPAGE_ACCESSED |  _RPAGE_RW |	  \
				 _RPAGE_DIRTY | _RPAGE_EXEC)
/*
 * _RPAGE_CHG_MASK masks of bits that are to be preserved across
 * pgprot changes
 */
#define _RPAGE_CHG_MASK        (RPTE_RPN_MASK | _RPAGE_DIRTY |	\
				_RPAGE_ACCESSED | _RPAGE_SPECIAL)
/* FIXME!! verify this again.
 * set of bits not changed in pmd_modify.
 * hashlinuxhugepage change mask.
 */
#define _RHPAGE_CHG_MASK (_RPAGE_CHG_MASK | _RPAGE_SPLITTING)

/*
 * Macro to mark a page protection value as "uncacheable".
 */

#define _RPAGE_CACHE_CTL	(_RPAGE_GUARDED | _RPAGE_NO_CACHE | \
				 _RPAGE_WRITETHRU)
/*
 * We define 2 sets of base prot bits, one for basic pages (ie,
 * cacheable kernel and user pages) and one for non cacheable
 * pages. We always set _RPAGE_COHERENT when SMP is enabled or
 * the processor might need it for DMA coherency.
 */
#define _RPAGE_BASE_NC		(_RPAGE_PRESENT | _RPAGE_ACCESSED)
#define _RPAGE_BASE		(_RPAGE_BASE_NC)

/* Permission masks used to generate the __RP and __S table,
 *
 * Note:__pgprot is defined in arch/powerpc/include/asm/page.h
 *
 * Write permissions imply read permissions for now (we could make write-only
 * pages on BookE but we don't bother for now). Execute permission control is
 * possible on platforms that define _RPAGE_EXEC
 *
 * Note due to the way vm flags are laid out, the bits are XWR
 */
#define RPAGE_NONE	__pgprot(_RPAGE_BASE)
#define RPAGE_SHARED	__pgprot(_RPAGE_BASE | _RPAGE_USER | _RPAGE_RW)
#define RPAGE_SHARED_X	__pgprot(_RPAGE_BASE | _RPAGE_USER | _RPAGE_RW | _RPAGE_EXEC)
#define RPAGE_COPY	__pgprot(_RPAGE_BASE | _RPAGE_USER)
#define RPAGE_COPY_X	__pgprot(_RPAGE_BASE | _RPAGE_USER | _RPAGE_EXEC)
#define RPAGE_READONLY	__pgprot(_RPAGE_BASE | _RPAGE_USER)
#define RPAGE_READONLY_X	__pgprot(_RPAGE_BASE | _RPAGE_USER | _RPAGE_EXEC)

#define __RP000		RPAGE_NONE
#define __RP001		RPAGE_READONLY
#define __RP010		RPAGE_COPY
#define __RP011		RPAGE_COPY
#define __RP100		RPAGE_READONLY_X
#define __RP101		RPAGE_READONLY_X
#define __RP110		RPAGE_COPY_X
#define __RP111		RPAGE_COPY_X

#define __RS000		RPAGE_NONE
#define __RS001		RPAGE_READONLY
#define __RS010		RPAGE_SHARED
#define __RS011		RPAGE_SHARED
#define __RS100		RPAGE_READONLY_X
#define __RS101		RPAGE_READONLY_X
#define __RS110		RPAGE_SHARED_X
#define __RS111		RPAGE_SHARED_X

/* Permission masks used for kernel mappings */
#define RPAGE_KERNEL		__pgprot(_RPAGE_BASE | _RPAGE_KERNEL_RW)
#define RPAGE_KERNEL_NC		__pgprot(_RPAGE_BASE_NC | _RPAGE_KERNEL_RW | \
					_RPAGE_NO_CACHE)
#define RPAGE_KERNEL_NCG	__pgprot(_RPAGE_BASE_NC | _RPAGE_KERNEL_RW | \
					_RPAGE_NO_CACHE | _RPAGE_GUARDED)
#define RPAGE_KERNEL_X		__pgprot(_RPAGE_BASE | _RPAGE_KERNEL_RWX)
#define RPAGE_KERNEL_RO		__pgprot(_RPAGE_BASE | _RPAGE_KERNEL_RO)
#define RPAGE_KERNEL_ROX	__pgprot(_RPAGE_BASE | _RPAGE_KERNEL_ROX)

/* Protection used for kernel text. We want the debuggers to be able to
 * set breakpoints anywhere, so don't write protect the kernel text
 * on platforms where such control is possible.
 */
#if defined(CONFIG_KGDB) || defined(CONFIG_XMON) || \
	defined(CONFIG_BDI_SWITCH) || defined(CONFIG_KPROBES) ||\
	defined(CONFIG_DYNAMIC_FTRACE)
#define RPAGE_KERNEL_TEXT	RPAGE_KERNEL_X
#else
#define RPAGE_KERNEL_TEXT	RPAGE_KERNEL_ROX
#endif

/* Make modules code happy. We don't set RO yet */
#define RPAGE_KERNEL_EXEC	RPAGE_KERNEL_X

#ifndef __ASSEMBLY__

#define RPTE_TABLE_SIZE	(sizeof(pte_t) << RPTE_INDEX_SIZE)
#define RPMD_TABLE_SIZE	(sizeof(pmd_t) << RPMD_INDEX_SIZE)
#define RPUD_TABLE_SIZE	(sizeof(pud_t) << RPUD_INDEX_SIZE)
#define RPGD_TABLE_SIZE	(sizeof(pgd_t) << RPGD_INDEX_SIZE)

static inline int rpte_index(unsigned long addr)
{
	return (addr >> PAGE_SHIFT) & (PTRS_PER_RPTE - 1);
}

/*
 * We encode swap type in the lower 5 bits. pfn is stored at the same place
 * as a normal pte. That leave us with few free bits to be used with swap
 */
#define r_swp_type(x)		(((x).val) & ((1UL << SWP_TYPE_BITS) - 1))
#define r_swp_offset(x)		((x).val >> RPTE_RPN_SHIFT)
#define r_swp_entry(type, offset)	((swp_entry_t) {		\
			(((type) & ((1UL << SWP_TYPE_BITS) - 1)) |	\
			 (((offset) << RPTE_RPN_SHIFT) & RPTE_RPN_MASK)) })

/* Atomic PTE updates */
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

static inline int __rptep_test_and_clear_young(struct mm_struct *mm,
					       unsigned long addr, pte_t *ptep)
{
	/*
	 * We could optimize this, based on spec. Leave
	 * it as it is for now.
	 */
	unsigned long old;

	if ((pte_val(*ptep) & _RPAGE_ACCESSED) == 0)
		return 0;
	old = rpte_update(mm, addr, ptep, _RPAGE_ACCESSED, 0, 0);
	return (old & _RPAGE_ACCESSED) != 0;
}

static inline void rptep_set_wrprotect(struct mm_struct *mm, unsigned long addr,
				       pte_t *ptep)
{

	if ((pte_val(*ptep) & _RPAGE_RW) == 0)
		return;

	rpte_update(mm, addr, ptep, _RPAGE_RW, 0, 0);
}

static inline void huge_rptep_set_wrprotect(struct mm_struct *mm,
					    unsigned long addr, pte_t *ptep)
{
	if ((pte_val(*ptep) & _RPAGE_RW) == 0)
		return;

	rpte_update(mm, addr, ptep, _RPAGE_RW, 0, 1);
}

/*
 * Set the dirty and/or accessed bits atomically in a linux PTE, this
 * function doesn't need to invalidate tlb.
 */
static inline void __rptep_set_access_flags(pte_t *ptep, pte_t entry)
{
	pte_t pte;
	unsigned long old_pte, new_pte;
	unsigned long set = pte_val(entry) & (_RPAGE_DIRTY | _RPAGE_ACCESSED |
					      _RPAGE_RW | _RPAGE_EXEC);
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

static inline int rpte_write(pte_t pte)
{
	return !!(pte_val(pte) & _RPAGE_RW);
}

static inline int rpte_dirty(pte_t pte)
{
	return !!(pte_val(pte) & _RPAGE_DIRTY);
}

static inline int rpte_young(pte_t pte)
{
	return !!(pte_val(pte) & _RPAGE_ACCESSED);
}

static inline int rpte_special(pte_t pte)
{
	return !!(pte_val(pte) & _RPAGE_SPECIAL);
}

static inline int rpte_none(pte_t pte)
{
	return (pte_val(pte) & ~_RPTE_NONE_MASK) == 0;
}

static inline pgprot_t rpte_pgprot(pte_t pte)
{
	return __pgprot(pte_val(pte) & RPAGE_PROT_BITS);
}

static inline int rpte_leaf(pte_t pte)
{
	return !!(pte_val(pte) & _RPAGE_LEAF);
}

static inline int rpte_present(pte_t pte)
{
	return !!(pte_val(pte) & _RPAGE_PRESENT);

}

#ifdef CONFIG_NUMA_BALANCING
static inline int rpte_protnone(pte_t pte)
{
#define _RPAGE_EAA_RWX (_RPAGE_EAA_R | _RPAGE_EAA_W | _RPAGE_EAA_X)
	return (pte_val(pte) &
		(_RPAGE_PRESENT | _RPAGE_EAA_RWX)) == _RPAGE_PRESENT;
}
#endif /* CONFIG_NUMA_BALANCING */

static inline pte_t pfn_rpte(unsigned long pfn, pgprot_t pgprot)
{
	/* FIXME!! check this again. This got updated */
	VM_BUG_ON((pfn << PAGE_SHIFT) & ~RPTE_RPN_MASK);
	return __pte(((pte_basic_t)(pfn) << PAGE_SHIFT) |
		     pgprot_val(pgprot));
}

static inline unsigned long rpte_pfn(pte_t pte)
{
	return (pte_val(pte) & RPTE_RPN_MASK) >> PAGE_SHIFT;
}

static inline pte_t rpte_wrprotect(pte_t pte)
{
	return __pte(pte_val(pte) & ~_RPAGE_RW);
}

static inline pte_t rpte_mkclean(pte_t pte)
{
	return __pte(pte_val(pte) & ~_RPAGE_DIRTY);
}

static inline pte_t rpte_mkold(pte_t pte)
{
	return __pte(pte_val(pte) & ~_RPAGE_ACCESSED);
}

static inline pte_t rpte_mkwrite(pte_t pte)
{
	return __pte(pte_val(pte) | _RPAGE_RW);
}

static inline pte_t rpte_mkdirty(pte_t pte)
{
	return __pte(pte_val(pte) | _RPAGE_DIRTY);
}

static inline pte_t rpte_mkyoung(pte_t pte)
{
	return __pte(pte_val(pte) | _RPAGE_ACCESSED);
}

static inline pte_t rpte_mkspecial(pte_t pte)
{
	return __pte(pte_val(pte) | _RPAGE_SPECIAL);
}

static inline pte_t rpte_mkhuge(pte_t pte)
{
	return pte;
}

static inline pte_t rpte_modify(pte_t pte, pgprot_t newprot)
{
	return __pte((pte_val(pte) & _RPAGE_CHG_MASK) | pgprot_val(newprot));
}

static inline void __set_rpte_at(struct mm_struct *mm, unsigned long addr,
				 pte_t *ptep, pte_t pte, int percpu)
{
	*ptep = pte;
	asm volatile("ptesync" : : : "memory");
}

static inline int rpmd_bad(pmd_t pmd)
{
	return !!(pmd_val(pmd) & RPMD_BAD_BITS);
}

static inline unsigned long rpmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)__va(pmd_val(pmd) & ~RPMD_MASKED_BITS);
}

static inline int rpmd_index(unsigned long addr)
{
	return (addr >> RPMD_SHIFT) & (PTRS_PER_RPMD - 1);
}

static inline int rpmd_same(pmd_t pmd_a, pmd_t pmd_b)
{
	return ((pmd_val(pmd_a) == pmd_val(pmd_b)));
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline int rpmd_trans_huge(pmd_t pmd)
{
	/*
	 * FIXME!! Verify this again, whether we need additional check
	 * WE just check leaf bit here.
	 */
	return !!(pmd_val(pmd) & _RPAGE_LEAF);
}

static inline int rpmd_trans_splitting(pmd_t pmd)
{
	if (rpmd_trans_huge(pmd))
		return pmd_val(pmd) & _RPAGE_SPLITTING;
	return 0;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

static inline int rpmd_large(pmd_t pmd)
{
	/*
	 * FIXME!! Verify this again, whether we need additional check
	 * WE just check leaf bit here.
	 */
	return !!(pmd_val(pmd) & _RPAGE_LEAF);
}

static inline int rpmd_huge(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _RPAGE_LEAF);
}

static inline pmd_t rpmd_mknotpresent(pmd_t pmd)
{
	return __pmd(pmd_val(pmd) & ~_RPAGE_PRESENT);
}

static inline pmd_t rpmd_mkhuge(pmd_t pmd)
{
	return __pmd(pmd_val(pmd) | _RPAGE_LEAF);
}

/* Move this FIXME!! */
static inline pmd_t rpmd_mksplitting(pmd_t pmd)
{
	return __pmd(pmd_val(pmd) | _RPAGE_SPLITTING);
}

extern unsigned long rpmd_hugepage_update(struct mm_struct *mm,
					  unsigned long addr, pmd_t *pmdp,
					  unsigned long clr, unsigned long set);
static inline int __rpmdp_test_and_clear_young(struct mm_struct *mm,
					       unsigned long addr, pmd_t *pmdp)
{
	unsigned long old;

	if ((pmd_val(*pmdp) & _RPAGE_ACCESSED) == 0)
		return 0;
	old = rpmd_hugepage_update(mm, addr, pmdp, _RPAGE_ACCESSED, 0);
	return ((old & _RPAGE_ACCESSED) != 0);
}

static inline int rpmdp_test_and_clear_young(struct vm_area_struct *vma,
					     unsigned long address, pmd_t *pmdp)
{
	return __rpmdp_test_and_clear_young(vma->vm_mm, address, pmdp);
}

static inline void rpmdp_set_wrprotect(struct mm_struct *mm, unsigned long addr,
				       pmd_t *pmdp)
{

	if ((pmd_val(*pmdp) & _RPAGE_RW) == 0)
		return;

	rpmd_hugepage_update(mm, addr, pmdp, _RPAGE_RW, 0);
}

static inline int rpud_bad(pud_t pud)
{
	return !!(pud_val(pud) & RPUD_BAD_BITS);
}

static inline unsigned long rpud_page_vaddr(pud_t pud)
{
	return (unsigned long)__va(pud_val(pud) & ~RPUD_MASKED_BITS);
}

static inline int rpud_index(unsigned long addr)
{
	return (addr >> RPUD_SHIFT) & (PTRS_PER_RPUD - 1);
}

static inline int rpud_huge(pud_t pud)
{
	return !!(pud_val(pud) & _RPAGE_LEAF);
}

static inline int rpgd_bad(pgd_t pgd)
{
	return !!(pgd_val(pgd) & RPGD_BAD_BITS);
}

static inline unsigned long rpgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long)__va(pgd_val(pgd) & ~RPGD_MASKED_BITS);
}

static inline int rpgd_index(unsigned long addr)
{
	return (addr >> RPGDIR_SHIFT) & (PTRS_PER_RPGD - 1);
}

static inline int rpgd_huge(pgd_t pgd)
{
	return !!(pgd_val(pgd) & _RPAGE_LEAF);
}

static inline int rhugepd_ok(hugepd_t hpd)
{
	return 0;
}

static inline int is_rhugepd(hugepd_t hpd)
{
	return 0;
}

static inline pgprot_t rpgprot_noncached(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~_RPAGE_CACHE_CTL) |
			_RPAGE_NO_CACHE | _RPAGE_GUARDED);
}

static inline pgprot_t rpgprot_noncached_wc(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~_RPAGE_CACHE_CTL) |
			_RPAGE_NO_CACHE);
}

static inline pgprot_t rpgprot_cached(pgprot_t prot)
{
	return __pgprot(pgprot_val(prot) & ~_RPAGE_CACHE_CTL);
}

static inline pgprot_t rpgprot_cached_wthru(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~_RPAGE_CACHE_CTL) |
			_RPAGE_WRITETHRU);
}

static inline pgprot_t rpgprot_cached_noncoherent(pgprot_t prot)
{
	return __pgprot(pgprot_val(prot) & ~_RPAGE_CACHE_CTL);
}

static inline pgprot_t rpgprot_writecombine(pgprot_t prot)
{
	return rpgprot_noncached_wc(prot);
}

static inline unsigned long rpte_io_cache_bits(void)
{
	return _RPAGE_NO_CACHE | _RPAGE_GUARDED;
}

static inline unsigned long gup_rpte_filter(int write)
{
	unsigned long mask;
	mask = _RPAGE_PRESENT | _RPAGE_USER;
	if (write)
		mask |= _RPAGE_RW;
	return mask;
}

extern void __meminit rvmemmap_create_mapping(unsigned long start,
					      unsigned long page_size,
					      unsigned long phys);
extern void rvmemmap_remove_mapping(unsigned long start,
				    unsigned long page_size);
extern pgprot_t rvm_get_page_prot(unsigned long vm_flags);
extern void rpgtable_cache_init(void);
extern int map_radix_kernel_page(unsigned long ea, unsigned long pa,
				 pgprot_t flags, unsigned int psz);
extern void set_rpte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
			pte_t pte);
extern pmd_t pfn_rpmd(unsigned long pfn, pgprot_t pgprot);
extern pmd_t mk_rpmd(struct page *page, pgprot_t pgprot);
extern pmd_t rpmd_modify(pmd_t pmd, pgprot_t newprot);
extern int r_has_transparent_hugepage(void);
extern void set_rpmd_at(struct mm_struct *mm, unsigned long addr,
			pmd_t *pmdp, pmd_t pmd);
extern int rpmdp_set_access_flags(struct vm_area_struct *vma,
				  unsigned long address, pmd_t *pmdp,
				  pmd_t entry, int dirty);
extern int rpmdp_test_and_clear_young(struct vm_area_struct *vma,
				      unsigned long address, pmd_t *pmdp);
extern pmd_t rpmdp_huge_get_and_clear(struct mm_struct *mm,
				      unsigned long addr, pmd_t *pmdp);
extern void rpmdp_splitting_flush(struct vm_area_struct *vma,
				  unsigned long address, pmd_t *pmdp);
extern pmd_t rpmdp_collapse_flush(struct vm_area_struct *vma,
				  unsigned long address, pmd_t *pmdp);
extern void rpgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
					pgtable_t pgtable);
extern pgtable_t rpgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp);
extern void rpmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
			     pmd_t *pmdp);
#endif /* __ASSEMBLY__ */
#endif
