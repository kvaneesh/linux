#ifndef _ASM_POWERPC_BOOK3S_64_HASH_H
#define _ASM_POWERPC_BOOK3S_64_HASH_H
#ifdef __KERNEL__

/*
 * Common bits between 4K and 64K pages in a linux-style PTE.
 * These match the bits in the (hardware-defined) PowerPC PTE as closely
 * as possible. Additional bits may be defined in pgtable-hash64-*.h
 *
 * Note: We only support user read/write permissions. Supervisor always
 * have full read/write to pages above PAGE_OFFSET (pages below that
 * always use the user access permissions).
 *
 * We could create separate kernel read-only if we used the 3 PP bits
 * combinations that newer processors provide but we currently don't.
 */
#define H_PAGE_PTE		0x00001
#define H_PAGE_PRESENT		0x00002 /* software: pte contains a translation */
#define H_PAGE_BIT_SWAP_TYPE	2
#define H_PAGE_USER		0x00004 /* matches one of the PP bits */
#define H_PAGE_EXEC		0x00008 /* No execute on POWER4 and newer (we invert) */
#define H_PAGE_GUARDED		0x00010
/* We can derive Memory coherence from _PAGE_NO_CACHE */
#define H_PAGE_COHERENT		0x0
#define H_PAGE_NO_CACHE		0x00020 /* I: cache inhibit */
#define H_PAGE_WRITETHRU		0x00040 /* W: cache write-through */
#define H_PAGE_DIRTY		0x00080 /* C: page changed */
#define H_PAGE_ACCESSED		0x00100 /* R: page referenced */
#define H_PAGE_RW		0x00200 /* software: user write access allowed */
#define H_PAGE_HASHPTE		0x00400 /* software: pte has an associated HPTE */
#define H_PAGE_BUSY		0x00800 /* software: PTE & hash are busy */
#define H_PAGE_F_GIX		0x07000 /* full page: hidx bits */
#define H_PAGE_F_GIX_SHIFT	12
#define H_PAGE_F_SECOND		0x08000 /* Whether to use secondary hash or not */
#define H_PAGE_SPECIAL		0x10000 /* software: special page */

/*
 * THP pages can't be special. So use the _PAGE_SPECIAL
 */
#define H_PAGE_SPLITTING H_PAGE_SPECIAL

/*
 * We need to differentiate between explicit huge page and THP huge
 * page, since THP huge page also need to track real subpage details
 */
#define H_PAGE_THP_HUGE  H_PAGE_4K_PFN

/*
 * set of bits not changed in pmd_modify.
 */
#define H_HPAGE_CHG_MASK (H_PTE_RPN_MASK | H_PAGE_HPTEFLAGS |		\
			   H_PAGE_DIRTY | H_PAGE_ACCESSED | H_PAGE_SPLITTING | \
			   H_PAGE_THP_HUGE | H_PAGE_PTE)

#ifdef CONFIG_PPC_64K_PAGES
#include <asm/book3s/64/hash-64k.h>
#else
#include <asm/book3s/64/hash-4k.h>
#endif

/*
 * Size of EA range mapped by our pagetables.
 */
#define H_PGTABLE_EADDR_SIZE	(H_PTE_INDEX_SIZE + H_PMD_INDEX_SIZE + \
				 H_PUD_INDEX_SIZE + H_PGD_INDEX_SIZE + PAGE_SHIFT)
#define H_PGTABLE_RANGE		(ASM_CONST(1) << H_PGTABLE_EADDR_SIZE)

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define H_PMD_CACHE_INDEX	(H_PMD_INDEX_SIZE + 1)
#else
#define H_PMD_CACHE_INDEX	H_PMD_INDEX_SIZE
#endif
/*
 * Define the address range of the kernel non-linear virtual area
 */
#define H_KERN_VIRT_START	ASM_CONST(0xD000000000000000)
#define H_KERN_VIRT_SIZE	ASM_CONST(0x0000100000000000)

/*
 * The vmalloc space starts at the beginning of that region, and
 * occupies half of it on hash CPUs and a quarter of it on Book3E
 * (we keep a quarter for the virtual memmap)
 */
#define H_VMALLOC_START	H_KERN_VIRT_START
#define H_VMALLOC_SIZE	(H_KERN_VIRT_SIZE >> 1)
#define H_VMALLOC_END	(H_VMALLOC_START + H_VMALLOC_SIZE)

/*
 * Region IDs
 */
#define REGION_SHIFT		60UL
#define REGION_MASK		(0xfUL << REGION_SHIFT)
#define REGION_ID(ea)		(((unsigned long)(ea)) >> REGION_SHIFT)

#define H_VMALLOC_REGION_ID	(REGION_ID(H_VMALLOC_START))
#define H_KERNEL_REGION_ID	(REGION_ID(PAGE_OFFSET))
#define H_VMEMMAP_REGION_ID	(0xfUL)	/* Server only */
#define H_USER_REGION_ID	(0UL)

/*
 * Defines the address of the vmemap area, in its own region on
 * hash table CPUs.
 */
#define H_VMEMMAP_BASE		(H_VMEMMAP_REGION_ID << REGION_SHIFT)

#ifdef CONFIG_PPC_MM_SLICES
#define HAVE_ARCH_UNMAPPED_AREA
#define HAVE_ARCH_UNMAPPED_AREA_TOPDOWN
#endif /* CONFIG_PPC_MM_SLICES */

/* No separate kernel read-only */
#define H_PAGE_KERNEL_RW	(H_PAGE_RW | H_PAGE_DIRTY) /* user access blocked by key */
#define _H_PAGE_KERNEL_RO	 H_PAGE_KERNEL_RW
#define H_PAGE_KERNEL_RWX	(H_PAGE_DIRTY | H_PAGE_RW | H_PAGE_EXEC)

/* Strong Access Ordering */
#define H_PAGE_SAO		(H_PAGE_WRITETHRU | H_PAGE_NO_CACHE | H_PAGE_COHERENT)

/* No page size encoding in the linux PTE */
#define H_PAGE_PSIZE		0

/* PTEIDX nibble */
#define H_PTEIDX_SECONDARY	0x8
#define H_PTEIDX_GROUP_IX	0x7

/* Hash table based platforms need atomic updates of the linux PTE */
#define PTE_ATOMIC_UPDATES	1
#define H_PTE_NONE_MASK	H_PAGE_HPTEFLAGS
/*
 * The mask convered by the RPN must be a ULL on 32-bit platforms with
 * 64-bit PTEs
 */
#define H_PTE_RPN_MASK	(~((1UL << H_PTE_RPN_SHIFT) - 1))
/*
 * _PAGE_CHG_MASK masks of bits that are to be preserved across
 * pgprot changes
 */
#define H_PAGE_CHG_MASK	(H_PTE_RPN_MASK | H_PAGE_HPTEFLAGS | H_PAGE_DIRTY | \
			 H_PAGE_ACCESSED | H_PAGE_SPECIAL | H_PAGE_PTE)
/*
 * Mask of bits returned by pte_pgprot()
 */
#define H_PAGE_PROT_BITS	(H_PAGE_GUARDED | H_PAGE_COHERENT | H_PAGE_NO_CACHE | \
				 H_PAGE_WRITETHRU | H_PAGE_4K_PFN |	\
				 H_PAGE_USER | H_PAGE_ACCESSED |	\
				 H_PAGE_RW |  H_PAGE_DIRTY | H_PAGE_EXEC)
/*
 * We define 2 sets of base prot bits, one for basic pages (ie,
 * cacheable kernel and user pages) and one for non cacheable
 * pages. We always set _PAGE_COHERENT when SMP is enabled or
 * the processor might need it for DMA coherency.
 */
#define H_PAGE_BASE_NC	(H_PAGE_PRESENT | H_PAGE_ACCESSED | H_PAGE_PSIZE)
#define H_PAGE_BASE	(H_PAGE_BASE_NC | H_PAGE_COHERENT)

/* Permission masks used to generate the __P and __S table,
 *
 * Note:__pgprot is defined in arch/powerpc/include/asm/page.h
 *
 * Write permissions imply read permissions for now (we could make write-only
 * pages on BookE but we don't bother for now). Execute permission control is
 * possible on platforms that define _PAGE_EXEC
 *
 * Note due to the way vm flags are laid out, the bits are XWR
 */
#define H_PAGE_NONE	__pgprot(H_PAGE_BASE)
#define H_PAGE_SHARED	__pgprot(H_PAGE_BASE | H_PAGE_USER | H_PAGE_RW)
#define H_PAGE_SHARED_X	__pgprot(H_PAGE_BASE | H_PAGE_USER | H_PAGE_RW | \
				 H_PAGE_EXEC)
#define H_PAGE_COPY	__pgprot(H_PAGE_BASE | H_PAGE_USER )
#define H_PAGE_COPY_X	__pgprot(H_PAGE_BASE | H_PAGE_USER | H_PAGE_EXEC)
#define H_PAGE_READONLY	__pgprot(H_PAGE_BASE | H_PAGE_USER )
#define H_PAGE_READONLY_X	__pgprot(H_PAGE_BASE | H_PAGE_USER | H_PAGE_EXEC)

#define __HP000	H_PAGE_NONE
#define __HP001	H_PAGE_READONLY
#define __HP010	H_PAGE_COPY
#define __HP011	H_PAGE_COPY
#define __HP100	H_PAGE_READONLY_X
#define __HP101	H_PAGE_READONLY_X
#define __HP110	H_PAGE_COPY_X
#define __HP111	H_PAGE_COPY_X

#define __HS000	H_PAGE_NONE
#define __HS001	H_PAGE_READONLY
#define __HS010	H_PAGE_SHARED
#define __HS011	H_PAGE_SHARED
#define __HS100	H_PAGE_READONLY_X
#define __HS101	H_PAGE_READONLY_X
#define __HS110	H_PAGE_SHARED_X
#define __HS111	H_PAGE_SHARED_X

/* Permission masks used for kernel mappings */
#define H_PAGE_KERNEL	__pgprot(H_PAGE_BASE | H_PAGE_KERNEL_RW)
#define H_PAGE_KERNEL_NC	__pgprot(H_PAGE_BASE_NC | H_PAGE_KERNEL_RW | \
				 H_PAGE_NO_CACHE)
#define H_PAGE_KERNEL_NCG	__pgprot(H_PAGE_BASE_NC | H_PAGE_KERNEL_RW | \
				 H_PAGE_NO_CACHE | H_PAGE_GUARDED)
#define H_PAGE_KERNEL_X	__pgprot(H_PAGE_BASE | H_PAGE_KERNEL_RWX)
#define H_PAGE_KERNEL_RO	__pgprot(H_PAGE_BASE | _H_PAGE_KERNEL_RO)
#define H_PAGE_KERNEL_ROX	__pgprot(_PAGE_BASE | _H_PAGE_KERNEL_ROX)

/* Protection used for kernel text. We want the debuggers to be able to
 * set breakpoints anywhere, so don't write protect the kernel text
 * on platforms where such control is possible.
 */
#if defined(CONFIG_KGDB) || defined(CONFIG_XMON) || defined(CONFIG_BDI_SWITCH) ||\
	defined(CONFIG_KPROBES) || defined(CONFIG_DYNAMIC_FTRACE)
#define H_PAGE_KERNEL_TEXT	H_PAGE_KERNEL_X
#else
#define H_PAGE_KERNEL_TEXT	H_PAGE_KERNEL_ROX
#endif

/* Make modules code happy. We don't set RO yet */
#define H_PAGE_KERNEL_EXEC	H_PAGE_KERNEL_X
#define H_PAGE_AGP		(H_PAGE_KERNEL_NC)

#define H_PMD_BAD_BITS		(H_PTE_TABLE_SIZE-1)
#define H_PUD_BAD_BITS		(H_PMD_TABLE_SIZE-1)

#ifndef __ASSEMBLY__
#define	pmd_bad(pmd)		(!is_kernel_addr(pmd_val(pmd)) \
				 || (pmd_val(pmd) & H_PMD_BAD_BITS))
#define pmd_page_vaddr(pmd)	(pmd_val(pmd) & ~H_PMD_MASKED_BITS)

#define	pud_bad(pud)		(!is_kernel_addr(pud_val(pud)) \
				 || (pud_val(pud) & H_PUD_BAD_BITS))
#define pud_page_vaddr(pud)	(pud_val(pud) & ~H_PUD_MASKED_BITS)

#define pgd_index(address) (((address) >> (H_PGDIR_SHIFT)) & (H_PTRS_PER_PGD - 1))
#define pud_index(address) (((address) >> (H_PUD_SHIFT)) & (H_PTRS_PER_PUD - 1))
#define pmd_index(address) (((address) >> (H_PMD_SHIFT)) & (H_PTRS_PER_PMD - 1))
#define pte_index(address) (((address) >> (PAGE_SHIFT)) & (H_PTRS_PER_PTE - 1))

/* Encode and de-code a swap entry */
#define MAX_SWAPFILES_CHECK() do {					\
		BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > SWP_TYPE_BITS);	\
		/*							\
		 * Don't have overlapping bits with _PAGE_HPTEFLAGS	\
		 * We filter HPTEFLAGS on set_pte.			\
		 */							\
		BUILD_BUG_ON(H_PAGE_HPTEFLAGS & (0x1f << H_PAGE_BIT_SWAP_TYPE)); \
	} while (0)
/*
 * on pte we don't need handle RADIX_TREE_EXCEPTIONAL_SHIFT;
 */
#define SWP_TYPE_BITS 5
#define __swp_type(x)		(((x).val >> H_PAGE_BIT_SWAP_TYPE)	\
				 & ((1UL << SWP_TYPE_BITS) - 1))
#define __swp_offset(x)		((x).val >> H_PTE_RPN_SHIFT)
#define __swp_entry(type, offset)	((swp_entry_t) {		\
			((type) << H_PAGE_BIT_SWAP_TYPE)		\
				| ((offset) << H_PTE_RPN_SHIFT) })

#define __pte_to_swp_entry(pte)		((swp_entry_t) { pte_val((pte)) })
#define __swp_entry_to_pte(x)		__pte((x).val)


extern void hpte_need_flush(struct mm_struct *mm, unsigned long addr,
			    pte_t *ptep, unsigned long pte, int huge);
extern unsigned long htab_convert_pte_flags(unsigned long pteflags);
/* Atomic PTE updates */
static inline unsigned long pte_update(struct mm_struct *mm,
				       unsigned long addr,
				       pte_t *ptep, unsigned long clr,
				       unsigned long set,
				       int huge)
{
	unsigned long old, tmp;

	__asm__ __volatile__(
	"1:	ldarx	%0,0,%3		# pte_update\n\
	andi.	%1,%0,%6\n\
	bne-	1b \n\
	andc	%1,%0,%4 \n\
	or	%1,%1,%7\n\
	stdcx.	%1,0,%3 \n\
	bne-	1b"
	: "=&r" (old), "=&r" (tmp), "=m" (*ptep)
	: "r" (ptep), "r" (clr), "m" (*ptep), "i" (H_PAGE_BUSY), "r" (set)
	: "cc" );
	/* huge pages use the old page table lock */
	if (!huge)
		assert_pte_locked(mm, addr);

	if (old & H_PAGE_HASHPTE)
		hpte_need_flush(mm, addr, ptep, old, huge);

	return old;
}

/*
 * We currently remove entries from the hashtable regardless of whether
 * the entry was young or dirty. The generic routines only flush if the
 * entry was young or dirty which is not good enough.
 *
 * We should be more intelligent about this but for the moment we override
 * these functions and force a tlb flush unconditionally
 */
static inline int __ptep_test_and_clear_young(struct mm_struct *mm,
					      unsigned long addr, pte_t *ptep)
{
	unsigned long old;

	if ((pte_val(*ptep) & (H_PAGE_ACCESSED | H_PAGE_HASHPTE)) == 0)
		return 0;
	old = pte_update(mm, addr, ptep, H_PAGE_ACCESSED, 0, 0);
	return (old & H_PAGE_ACCESSED) != 0;
}

#define __HAVE_ARCH_PTEP_SET_WRPROTECT
static inline void ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr,
				      pte_t *ptep)
{

	if ((pte_val(*ptep) & H_PAGE_RW) == 0)
		return;

	pte_update(mm, addr, ptep, H_PAGE_RW, 0, 0);
}

static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
					   unsigned long addr, pte_t *ptep)
{
	if ((pte_val(*ptep) & H_PAGE_RW) == 0)
		return;

	pte_update(mm, addr, ptep, H_PAGE_RW, 0, 1);
}


/* Set the dirty and/or accessed bits atomically in a linux PTE, this
 * function doesn't need to flush the hash entry
 */
static inline void __ptep_set_access_flags(pte_t *ptep, pte_t entry)
{
	unsigned long bits = pte_val(entry) &
		(H_PAGE_DIRTY | H_PAGE_ACCESSED | H_PAGE_RW | H_PAGE_EXEC);

	unsigned long old, tmp;

	__asm__ __volatile__(
	"1:	ldarx	%0,0,%4\n\
		andi.	%1,%0,%6\n\
		bne-	1b \n\
		or	%0,%3,%0\n\
		stdcx.	%0,0,%4\n\
		bne-	1b"
	:"=&r" (old), "=&r" (tmp), "=m" (*ptep)
	:"r" (bits), "r" (ptep), "m" (*ptep), "i" (H_PAGE_BUSY)
	:"cc");
}

static inline int pgd_bad(pgd_t pgd)
{
	return (pgd_val(pgd) == 0);
}

#define __HAVE_ARCH_PTE_SAME
#define pte_same(A,B)	(((pte_val(A) ^ pte_val(B)) & ~H_PAGE_HPTEFLAGS) == 0)
#define pgd_page_vaddr(pgd)	(pgd_val(pgd) & ~H_PGD_MASKED_BITS)


/* Generic accessors to PTE bits */
static inline int pte_write(pte_t pte)		{ return !!(pte_val(pte) & H_PAGE_RW);}
static inline int pte_dirty(pte_t pte)		{ return !!(pte_val(pte) & H_PAGE_DIRTY); }
static inline int pte_young(pte_t pte)		{ return !!(pte_val(pte) & H_PAGE_ACCESSED); }
static inline int pte_special(pte_t pte)	{ return !!(pte_val(pte) & H_PAGE_SPECIAL); }
static inline int pte_none(pte_t pte)		{ return (pte_val(pte) & ~H_PTE_NONE_MASK) == 0; }
static inline pgprot_t pte_pgprot(pte_t pte)	{ return __pgprot(pte_val(pte) & H_PAGE_PROT_BITS); }

#ifdef CONFIG_NUMA_BALANCING
/*
 * These work without NUMA balancing but the kernel does not care. See the
 * comment in include/asm-generic/pgtable.h . On powerpc, this will only
 * work for user pages and always return true for kernel pages.
 */
static inline int pte_protnone(pte_t pte)
{
	return (pte_val(pte) &
		(H_PAGE_PRESENT | H_PAGE_USER)) == H_PAGE_PRESENT;
}
#endif /* CONFIG_NUMA_BALANCING */

static inline int pte_present(pte_t pte)
{
	return pte_val(pte) & H_PAGE_PRESENT;
}

/* Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 *
 * Even if PTEs can be unsigned long long, a PFN is always an unsigned
 * long for now.
 */
static inline pte_t pfn_pte(unsigned long pfn, pgprot_t pgprot)
{
	return __pte(((pte_basic_t)(pfn) << H_PTE_RPN_SHIFT) |
		     pgprot_val(pgprot));
}

static inline unsigned long pte_pfn(pte_t pte)
{
	return pte_val(pte) >> H_PTE_RPN_SHIFT;
}

/* Generic modifiers for PTE bits */
static inline pte_t pte_wrprotect(pte_t pte)
{
	return __pte(pte_val(pte) & ~H_PAGE_RW);
}

static inline pte_t pte_mkclean(pte_t pte)
{
	return __pte(pte_val(pte) & ~H_PAGE_DIRTY);
}

static inline pte_t pte_mkold(pte_t pte)
{
	return __pte(pte_val(pte) & ~H_PAGE_ACCESSED);
}

static inline pte_t pte_mkwrite(pte_t pte)
{
	return __pte(pte_val(pte) | H_PAGE_RW);
}

static inline pte_t pte_mkdirty(pte_t pte)
{
	return __pte(pte_val(pte) | H_PAGE_DIRTY);
}

static inline pte_t pte_mkyoung(pte_t pte)
{
	return __pte(pte_val(pte) | H_PAGE_ACCESSED);
}

static inline pte_t pte_mkspecial(pte_t pte)
{
	return __pte(pte_val(pte) | H_PAGE_SPECIAL);
}

static inline pte_t pte_mkhuge(pte_t pte)
{
	return pte;
}

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	return __pte((pte_val(pte) & H_PAGE_CHG_MASK) | pgprot_val(newprot));
}

/* This low level function performs the actual PTE insertion
 * Setting the PTE depends on the MMU type and other factors. It's
 * an horrible mess that I'm not going to try to clean up now but
 * I'm keeping it in one place rather than spread around
 */
static inline void __set_pte_at(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep, pte_t pte, int percpu)
{
	/*
	 * Anything else just stores the PTE normally. That covers all 64-bit
	 * cases, and 32-bit non-hash with 32-bit PTEs.
	 */
	*ptep = pte;
}

/*
 * Macro to mark a page protection value as "uncacheable".
 */

#define H_PAGE_CACHE_CTL	(H_PAGE_COHERENT | H_PAGE_GUARDED | H_PAGE_NO_CACHE | \
				 H_PAGE_WRITETHRU)

#define pgprot_noncached pgprot_noncached
static inline pgprot_t pgprot_noncached(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~H_PAGE_CACHE_CTL) |
			H_PAGE_NO_CACHE | H_PAGE_GUARDED);
}

#define pgprot_noncached_wc pgprot_noncached_wc
static inline pgprot_t pgprot_noncached_wc(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~H_PAGE_CACHE_CTL) |
			H_PAGE_NO_CACHE);
}

#define pgprot_cached pgprot_cached
static inline pgprot_t pgprot_cached(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~H_PAGE_CACHE_CTL) |
			H_PAGE_COHERENT);
}

#define pgprot_cached_wthru pgprot_cached_wthru
static inline pgprot_t pgprot_cached_wthru(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~H_PAGE_CACHE_CTL) |
			H_PAGE_COHERENT | H_PAGE_WRITETHRU);
}

#define pgprot_cached_noncoherent pgprot_cached_noncoherent
static inline pgprot_t pgprot_cached_noncoherent(pgprot_t prot)
{
	return __pgprot(pgprot_val(prot) & ~H_PAGE_CACHE_CTL);
}

#define pgprot_writecombine pgprot_writecombine
static inline pgprot_t pgprot_writecombine(pgprot_t prot)
{
	return pgprot_noncached_wc(prot);
}

extern pgprot_t vm_get_page_prot(unsigned long vm_flags);
#define vm_get_page_prot vm_get_page_prot

static inline unsigned long pte_io_cache_bits(void)
{
	return H_PAGE_NO_CACHE | H_PAGE_GUARDED;
}

static inline unsigned long gup_pte_filter(int write)
{
	unsigned long mask;
	mask = H_PAGE_PRESENT | H_PAGE_USER;
	if (write)
		mask |= H_PAGE_RW;
	return mask;
}

static inline unsigned long ioremap_prot_flags(unsigned long flags)
{
	/* writeable implies dirty for kernel addresses */
	if (flags & H_PAGE_RW)
		flags |= H_PAGE_DIRTY;

	/* we don't want to let _PAGE_USER and _PAGE_EXEC leak out */
	flags &= ~(H_PAGE_USER | H_PAGE_EXEC);
	return flags;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
extern void hpte_do_hugepage_flush(struct mm_struct *mm, unsigned long addr,
				   pmd_t *pmdp, unsigned long old_pmd);
#else
static inline void hpte_do_hugepage_flush(struct mm_struct *mm,
					  unsigned long addr, pmd_t *pmdp,
					  unsigned long old_pmd)
{
	WARN(1, "%s called with THP disabled\n", __func__);
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

extern int map_kernel_page(unsigned long ea, unsigned long pa, int flags);
#endif /* !__ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif /* _ASM_POWERPC_BOOK3S_64_HASH_H */
