#ifndef _ASM_POWERPC_PGTABLE_H
#define _ASM_POWERPC_PGTABLE_H
#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <asm/processor.h>		/* For TASK_SIZE */
#include <asm/mmu.h>
#include <asm/page.h>

struct mm_struct;

#endif /* !__ASSEMBLY__ */

#if defined(CONFIG_PPC64)
#  include <asm/pgtable-ppc64.h>
#else
#  include <asm/pgtable-ppc32.h>
#endif

/*
 * We save the slot number & secondary bit in the second half of the
 * PTE page. We use the 8 bytes per each pte entry.
 */
#define PTE_PAGE_HIDX_OFFSET (PTRS_PER_PTE * 8)

/* A large part matches with pte bits */
#define PMD_HUGE_PRESENT	0x001 /* software: pte contains a translation */
#define PMD_HUGE_USER		0x002 /* matches one of the PP bits */
#define PMD_HUGE_FILE		0x002 /* (!present only) software: pte holds file offset */
#define PMD_HUGE_EXEC		0x004 /* No execute on POWER4 and newer (we invert) */
#define PMD_HUGE_SPLITTING	0x008
#define PMD_HUGE_SAO		0x010 /* strong Access order */
#define PMD_HUGE_HASHPTE	0x020
#define PMD_ISHUGE		0x040
#define PMD_HUGE_DIRTY		0x080 /* C: page changed */
#define PMD_HUGE_ACCESSED	0x100 /* R: page referenced */
#define PMD_HUGE_RW		0x200 /* software: user write access allowed */
#define PMD_HUGE_BUSY		0x800 /* software: PTE & hash are busy */
#define PMD_HUGE_HPTEFLAGS	(PMD_HUGE_BUSY | PMD_HUGE_HASHPTE)
/*
 * We keep both the pmd and pte rpn shift same, eventhough we use only
 * lower 12 bits for hugepage flags at pmd level
 */
#define PMD_HUGE_RPN_SHIFT	PTE_RPN_SHIFT
#define HUGE_PAGE_SIZE		(ASM_CONST(1) << 24)
#define HUGE_PAGE_MASK		(~(HUGE_PAGE_SIZE - 1))

#ifndef __ASSEMBLY__
extern void hpte_need_hugepage_flush(struct mm_struct *mm, unsigned long addr,
				     pmd_t *pmdp);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
extern pmd_t pfn_pmd(unsigned long pfn, pgprot_t pgprot);
extern pmd_t mk_pmd(struct page *page, pgprot_t pgprot);
extern pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot);
extern void set_pmd_at(struct mm_struct *mm, unsigned long addr,
		       pmd_t *pmdp, pmd_t pmd);
extern void update_mmu_cache_pmd(struct vm_area_struct *vma, unsigned long addr,
				 pmd_t *pmd);
static inline int pmd_large(pmd_t pmd)
{
	return (pmd_val(pmd) & (PMD_ISHUGE | PMD_HUGE_PRESENT)) ==
		(PMD_ISHUGE | PMD_HUGE_PRESENT);
}

static inline int pmd_trans_splitting(pmd_t pmd)
{
	return (pmd_val(pmd) & (PMD_ISHUGE|PMD_HUGE_SPLITTING)) ==
		(PMD_ISHUGE|PMD_HUGE_SPLITTING);
}

static inline int pmd_trans_huge(pmd_t pmd)
{
	return pmd_val(pmd) & PMD_ISHUGE;
}
/* We will enable it in the last patch */
#define has_transparent_hugepage() 0
#else
#define pmd_large(pmd)		0
#define has_transparent_hugepage() 0
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

static inline unsigned long pmd_pfn(pmd_t pmd)
{
	/*
	 * Only called for hugepage pmd
	 */
	return pmd_val(pmd) >> PMD_HUGE_RPN_SHIFT;
}

static inline int pmd_young(pmd_t pmd)
{
	return pmd_val(pmd) & PMD_HUGE_ACCESSED;
}

static inline pmd_t pmd_mkhuge(pmd_t pmd)
{
	/* Do nothing, mk_pmd() does this part.  */
	return pmd;
}

#define __HAVE_ARCH_PMD_WRITE
static inline int pmd_write(pmd_t pmd)
{
	return pmd_val(pmd) & PMD_HUGE_RW;
}

static inline pmd_t pmd_mkold(pmd_t pmd)
{
	pmd_val(pmd) &= ~PMD_HUGE_ACCESSED;
	return pmd;
}

static inline pmd_t pmd_wrprotect(pmd_t pmd)
{
	pmd_val(pmd) &= ~PMD_HUGE_RW;
	return pmd;
}

static inline pmd_t pmd_mkdirty(pmd_t pmd)
{
	pmd_val(pmd) |= PMD_HUGE_DIRTY;
	return pmd;
}

static inline pmd_t pmd_mkyoung(pmd_t pmd)
{
	pmd_val(pmd) |= PMD_HUGE_ACCESSED;
	return pmd;
}

static inline pmd_t pmd_mkwrite(pmd_t pmd)
{
	pmd_val(pmd) |= PMD_HUGE_RW;
	return pmd;
}

static inline pmd_t pmd_mknotpresent(pmd_t pmd)
{
	pmd_val(pmd) &= ~PMD_HUGE_PRESENT;
	return pmd;
}

static inline pmd_t pmd_mksplitting(pmd_t pmd)
{
	pmd_val(pmd) |= PMD_HUGE_SPLITTING;
	return pmd;
}

/*
 * Set the dirty and/or accessed bits atomically in a linux hugepage PMD, this
 * function doesn't need to flush the hash entry
 */
static inline void __pmdp_set_access_flags(pmd_t *pmdp, pmd_t entry)
{
	unsigned long bits = pmd_val(entry) & (PMD_HUGE_DIRTY |
					       PMD_HUGE_ACCESSED |
					       PMD_HUGE_RW | PMD_HUGE_EXEC);
#ifdef PTE_ATOMIC_UPDATES
	unsigned long old, tmp;

	__asm__ __volatile__(
	"1:	ldarx	%0,0,%4\n\
		andi.	%1,%0,%6\n\
		bne-	1b \n\
		or	%0,%3,%0\n\
		stdcx.	%0,0,%4\n\
		bne-	1b"
	:"=&r" (old), "=&r" (tmp), "=m" (*pmdp)
	:"r" (bits), "r" (pmdp), "m" (*pmdp), "i" (PMD_HUGE_BUSY)
	:"cc");
#else
	unsigned long old = pmd_val(*pmdp);
	*pmdp = __pmd(old | bits);
#endif
}

#define __HAVE_ARCH_PMD_SAME
static inline int pmd_same(pmd_t pmd_a, pmd_t pmd_b)
{
	return (((pmd_val(pmd_a) ^ pmd_val(pmd_b)) & ~PMD_HUGE_HPTEFLAGS) == 0);
}

#define __HAVE_ARCH_PMDP_SET_ACCESS_FLAGS
extern int pmdp_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp,
				 pmd_t entry, int dirty);

static inline unsigned long pmd_hugepage_update(struct mm_struct *mm,
						unsigned long addr,
						pmd_t *pmdp, unsigned long clr)
{
#ifdef PTE_ATOMIC_UPDATES
	unsigned long old, tmp;

	__asm__ __volatile__(
	"1:	ldarx	%0,0,%3\n\
		andi.	%1,%0,%6\n\
		bne-	1b \n\
		andc	%1,%0,%4 \n\
		stdcx.	%1,0,%3 \n\
		bne-	1b"
	: "=&r" (old), "=&r" (tmp), "=m" (*pmdp)
	: "r" (pmdp), "r" (clr), "m" (*pmdp), "i" (PMD_HUGE_BUSY)
	: "cc" );
#else
	unsigned long old = pmd_val(*pmdp);
	*pmdp = __pmd(old & ~clr);
#endif

#ifdef CONFIG_PPC_STD_MMU_64
	if (old & PMD_HUGE_HASHPTE)
		hpte_need_hugepage_flush(mm, addr, pmdp);
#endif
	return old;
}

static inline int __pmdp_test_and_clear_young(struct mm_struct *mm,
					      unsigned long addr, pmd_t *pmdp)
{
	unsigned long old;

	if ((pmd_val(*pmdp) & (PMD_HUGE_ACCESSED | PMD_HUGE_HASHPTE)) == 0)
		return 0;
	old = pmd_hugepage_update(mm, addr, pmdp, PMD_HUGE_ACCESSED);
	return ((old & PMD_HUGE_ACCESSED) != 0);
}

#define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
extern int pmdp_test_and_clear_young(struct vm_area_struct *vma,
				     unsigned long address, pmd_t *pmdp);
#define __HAVE_ARCH_PMDP_CLEAR_YOUNG_FLUSH
extern int pmdp_clear_flush_young(struct vm_area_struct *vma,
				  unsigned long address, pmd_t *pmdp);

#define __HAVE_ARCH_PMDP_GET_AND_CLEAR
static inline pmd_t pmdp_get_and_clear(struct mm_struct *mm,
				       unsigned long addr, pmd_t *pmdp)
{
	unsigned long old = pmd_hugepage_update(mm, addr, pmdp, ~0UL);
	return __pmd(old);
}

#define __HAVE_ARCH_PMDP_SET_WRPROTECT
static inline void pmdp_set_wrprotect(struct mm_struct *mm, unsigned long addr,
				      pmd_t *pmdp)
{

	if ((pmd_val(*pmdp) & PMD_HUGE_RW) == 0)
		return;

	pmd_hugepage_update(mm, addr, pmdp, PMD_HUGE_RW);
}

#define __HAVE_ARCH_PMDP_SPLITTING_FLUSH
extern void pmdp_splitting_flush(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp);

#define __HAVE_ARCH_PGTABLE_DEPOSIT
extern void pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				       pgtable_t pgtable);
#define __HAVE_ARCH_PGTABLE_WITHDRAW
extern pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp);

#define __HAVE_ARCH_PMDP_INVALIDATE
extern void pmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
			    pmd_t *pmdp);

#include <asm/tlbflush.h>

/* Generic accessors to PTE bits */
static inline int pte_write(pte_t pte)		{ return pte_val(pte) & _PAGE_RW; }
static inline int pte_dirty(pte_t pte)		{ return pte_val(pte) & _PAGE_DIRTY; }
static inline int pte_young(pte_t pte)		{ return pte_val(pte) & _PAGE_ACCESSED; }
static inline int pte_file(pte_t pte)		{ return pte_val(pte) & _PAGE_FILE; }
static inline int pte_special(pte_t pte)	{ return pte_val(pte) & _PAGE_SPECIAL; }
static inline int pte_present(pte_t pte)	{ return pte_val(pte) & _PAGE_PRESENT; }
static inline int pte_none(pte_t pte)		{ return (pte_val(pte) & ~_PTE_NONE_MASK) == 0; }
static inline pgprot_t pte_pgprot(pte_t pte)	{ return __pgprot(pte_val(pte) & PAGE_PROT_BITS); }

/* Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 *
 * Even if PTEs can be unsigned long long, a PFN is always an unsigned
 * long for now.
 */
static inline pte_t pfn_pte(unsigned long pfn, pgprot_t pgprot) {
	return __pte(((pte_basic_t)(pfn) << PTE_RPN_SHIFT) |
		     pgprot_val(pgprot)); }
static inline unsigned long pte_pfn(pte_t pte)	{
	return pte_val(pte) >> PTE_RPN_SHIFT; }

/* Keep these as a macros to avoid include dependency mess */
#define pte_page(x)		pfn_to_page(pte_pfn(x))
#define mk_pte(page, pgprot)	pfn_pte(page_to_pfn(page), (pgprot))

/* Generic modifiers for PTE bits */
static inline pte_t pte_wrprotect(pte_t pte) {
	pte_val(pte) &= ~(_PAGE_RW | _PAGE_HWWRITE); return pte; }
static inline pte_t pte_mkclean(pte_t pte) {
	pte_val(pte) &= ~(_PAGE_DIRTY | _PAGE_HWWRITE); return pte; }
static inline pte_t pte_mkold(pte_t pte) {
	pte_val(pte) &= ~_PAGE_ACCESSED; return pte; }
static inline pte_t pte_mkwrite(pte_t pte) {
	pte_val(pte) |= _PAGE_RW; return pte; }
static inline pte_t pte_mkdirty(pte_t pte) {
	pte_val(pte) |= _PAGE_DIRTY; return pte; }
static inline pte_t pte_mkyoung(pte_t pte) {
	pte_val(pte) |= _PAGE_ACCESSED; return pte; }
static inline pte_t pte_mkspecial(pte_t pte) {
	pte_val(pte) |= _PAGE_SPECIAL; return pte; }
static inline pte_t pte_mkhuge(pte_t pte) {
	return pte; }
static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	pte_val(pte) = (pte_val(pte) & _PAGE_CHG_MASK) | pgprot_val(newprot);
	return pte;
}


/* Insert a PTE, top-level function is out of line. It uses an inline
 * low level function in the respective pgtable-* files
 */
extern void set_pte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
		       pte_t pte);

/* This low level function performs the actual PTE insertion
 * Setting the PTE depends on the MMU type and other factors. It's
 * an horrible mess that I'm not going to try to clean up now but
 * I'm keeping it in one place rather than spread around
 */
static inline void __set_pte_at(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep, pte_t pte, int percpu)
{
#if defined(CONFIG_PPC_STD_MMU_32) && defined(CONFIG_SMP) && !defined(CONFIG_PTE_64BIT)
	/* First case is 32-bit Hash MMU in SMP mode with 32-bit PTEs. We use the
	 * helper pte_update() which does an atomic update. We need to do that
	 * because a concurrent invalidation can clear _PAGE_HASHPTE. If it's a
	 * per-CPU PTE such as a kmap_atomic, we do a simple update preserving
	 * the hash bits instead (ie, same as the non-SMP case)
	 */
	if (percpu)
		*ptep = __pte((pte_val(*ptep) & _PAGE_HASHPTE)
			      | (pte_val(pte) & ~_PAGE_HASHPTE));
	else
		pte_update(ptep, ~_PAGE_HASHPTE, pte_val(pte));

#elif defined(CONFIG_PPC32) && defined(CONFIG_PTE_64BIT)
	/* Second case is 32-bit with 64-bit PTE.  In this case, we
	 * can just store as long as we do the two halves in the right order
	 * with a barrier in between. This is possible because we take care,
	 * in the hash code, to pre-invalidate if the PTE was already hashed,
	 * which synchronizes us with any concurrent invalidation.
	 * In the percpu case, we also fallback to the simple update preserving
	 * the hash bits
	 */
	if (percpu) {
		*ptep = __pte((pte_val(*ptep) & _PAGE_HASHPTE)
			      | (pte_val(pte) & ~_PAGE_HASHPTE));
		return;
	}
#if _PAGE_HASHPTE != 0
	if (pte_val(*ptep) & _PAGE_HASHPTE)
		flush_hash_entry(mm, ptep, addr);
#endif
	__asm__ __volatile__("\
		stw%U0%X0 %2,%0\n\
		eieio\n\
		stw%U0%X0 %L2,%1"
	: "=m" (*ptep), "=m" (*((unsigned char *)ptep+4))
	: "r" (pte) : "memory");

#elif defined(CONFIG_PPC_STD_MMU_32)
	/* Third case is 32-bit hash table in UP mode, we need to preserve
	 * the _PAGE_HASHPTE bit since we may not have invalidated the previous
	 * translation in the hash yet (done in a subsequent flush_tlb_xxx())
	 * and see we need to keep track that this PTE needs invalidating
	 */
	*ptep = __pte((pte_val(*ptep) & _PAGE_HASHPTE)
		      | (pte_val(pte) & ~_PAGE_HASHPTE));

#else
	/* Anything else just stores the PTE normally. That covers all 64-bit
	 * cases, and 32-bit non-hash with 32-bit PTEs.
	 */
	*ptep = pte;
#endif
}


#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
extern int ptep_set_access_flags(struct vm_area_struct *vma, unsigned long address,
				 pte_t *ptep, pte_t entry, int dirty);

/*
 * Macro to mark a page protection value as "uncacheable".
 */

#define _PAGE_CACHE_CTL	(_PAGE_COHERENT | _PAGE_GUARDED | _PAGE_NO_CACHE | \
			 _PAGE_WRITETHRU)

#define pgprot_noncached(prot)	  (__pgprot((pgprot_val(prot) & ~_PAGE_CACHE_CTL) | \
				            _PAGE_NO_CACHE | _PAGE_GUARDED))

#define pgprot_noncached_wc(prot) (__pgprot((pgprot_val(prot) & ~_PAGE_CACHE_CTL) | \
				            _PAGE_NO_CACHE))

#define pgprot_cached(prot)       (__pgprot((pgprot_val(prot) & ~_PAGE_CACHE_CTL) | \
				            _PAGE_COHERENT))

#define pgprot_cached_wthru(prot) (__pgprot((pgprot_val(prot) & ~_PAGE_CACHE_CTL) | \
				            _PAGE_COHERENT | _PAGE_WRITETHRU))

#define pgprot_cached_noncoherent(prot) \
		(__pgprot(pgprot_val(prot) & ~_PAGE_CACHE_CTL))

#define pgprot_writecombine pgprot_noncached_wc

struct file;
extern pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
				     unsigned long size, pgprot_t vma_prot);
#define __HAVE_PHYS_MEM_ACCESS_PROT

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
extern unsigned long empty_zero_page[];
#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

extern pgd_t swapper_pg_dir[];

extern void paging_init(void);

/*
 * kern_addr_valid is intended to indicate whether an address is a valid
 * kernel address.  Most 32-bit archs define it as always true (like this)
 * but most 64-bit archs actually perform a test.  What should we do here?
 */
#define kern_addr_valid(addr)	(1)

#define io_remap_pfn_range(vma, vaddr, pfn, size, prot)		\
		remap_pfn_range(vma, vaddr, pfn, size, prot)

#include <asm-generic/pgtable.h>


/*
 * This gets called at the end of handling a page fault, when
 * the kernel has put a new PTE into the page table for the process.
 * We use it to ensure coherency between the i-cache and d-cache
 * for the page which has just been mapped in.
 * On machines which use an MMU hash table, we use this to put a
 * corresponding HPTE into the hash table ahead of time, instead of
 * waiting for the inevitable extra hash-table miss exception.
 */
extern void update_mmu_cache(struct vm_area_struct *, unsigned long, pte_t *);

extern int gup_hugepd(hugepd_t *hugepd, unsigned pdshift, unsigned long addr,
		      unsigned long end, int write, struct page **pages, int *nr);

#endif /* __ASSEMBLY__ */

#endif /* __KERNEL__ */
#endif /* _ASM_POWERPC_PGTABLE_H */
