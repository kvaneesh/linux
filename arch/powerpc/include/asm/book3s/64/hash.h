#ifndef _ASM_POWERPC_BOOK3S_64_HASH_H
#define _ASM_POWERPC_BOOK3S_64_HASH_H
#ifdef __KERNEL__
#ifndef __ASSEMBLY__
#include <asm/cmpxchg.h>
#endif

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
#define	hlpmd_bad(pmd)		(!is_kernel_addr(pmd_val(pmd))		\
				 || (pmd_val(pmd) & H_PMD_BAD_BITS))
#define hlpmd_page_vaddr(pmd)	(pmd_val(pmd) & ~H_PMD_MASKED_BITS)

#define	hlpud_bad(pud)		(!is_kernel_addr(pud_val(pud))		\
				 || (pud_val(pud) & H_PUD_BAD_BITS))
#define hlpud_page_vaddr(pud)	(pud_val(pud) & ~H_PUD_MASKED_BITS)

#define hlpgd_index(address) (((address) >> (H_PGDIR_SHIFT)) & (H_PTRS_PER_PGD - 1))
#define hlpud_index(address) (((address) >> (H_PUD_SHIFT)) & (H_PTRS_PER_PUD - 1))
#define hlpmd_index(address) (((address) >> (H_PMD_SHIFT)) & (H_PTRS_PER_PMD - 1))
#define hlpte_index(address) (((address) >> (PAGE_SHIFT)) & (H_PTRS_PER_PTE - 1))

/*
 * on pte we don't need handle RADIX_TREE_EXCEPTIONAL_SHIFT;
 * We encode swap type in the lower part of pte, skipping the lowest two bits.
 * Offset is encoded as pfn.
 */
#define hl_swp_type(x)		(((x).val >> H_PAGE_BIT_SWAP_TYPE)	\
				 & ((1UL << SWP_TYPE_BITS) - 1))
#define hl_swp_offset(x)	((x).val >> H_PTE_RPN_SHIFT)
#define hl_swp_entry(type, offset)	((swp_entry_t) {		\
				((type) << H_PAGE_BIT_SWAP_TYPE)	\
				| ((offset) << H_PTE_RPN_SHIFT) })


extern void hpte_need_flush(struct mm_struct *mm, unsigned long addr,
			    pte_t *ptep, unsigned long pte, int huge);
extern unsigned long htab_convert_pte_flags(unsigned long pteflags);
/* Atomic PTE updates */
static inline unsigned long hlpte_update(struct mm_struct *mm,
					 unsigned long addr,
					 pte_t *ptep, unsigned long clr,
					 unsigned long set,
					 int huge)
{
	pte_t pte;
	unsigned long old_pte, new_pte;

	do {
reload:
		pte = READ_ONCE(*ptep);
		old_pte = pte_val(pte);

		/* If PTE busy, retry */
		if (unlikely(old_pte & H_PAGE_BUSY))
			goto reload;
		/*
		 * Try to lock the PTE, add ACCESSED and DIRTY if it was
		 * a write access. Since this is 4K insert of 64K page size
		 * also add _PAGE_COMBO
		 */
		new_pte = (old_pte | set) & ~clr;

	} while (cpu_to_be64(old_pte) != __cmpxchg_u64((unsigned long *)ptep,
						   cpu_to_be64(old_pte),
						   cpu_to_be64(new_pte)));

	/* huge pages use the old page table lock */
	if (!huge)
		assert_pte_locked(mm, addr);

	if (old_pte & H_PAGE_HASHPTE)
		hpte_need_flush(mm, addr, ptep, old_pte, huge);

	return old_pte;
}

/*
 * We currently remove entries from the hashtable regardless of whether
 * the entry was young or dirty. The generic routines only flush if the
 * entry was young or dirty which is not good enough.
 *
 * We should be more intelligent about this but for the moment we override
 * these functions and force a tlb flush unconditionally
 */
static inline int __hlptep_test_and_clear_young(struct mm_struct *mm,
					      unsigned long addr, pte_t *ptep)
{
	unsigned long old;

	if ((pte_val(*ptep) & (H_PAGE_ACCESSED | H_PAGE_HASHPTE)) == 0)
		return 0;
	old = hlpte_update(mm, addr, ptep, H_PAGE_ACCESSED, 0, 0);
	return (old & H_PAGE_ACCESSED) != 0;
}

static inline void hlptep_set_wrprotect(struct mm_struct *mm, unsigned long addr,
				      pte_t *ptep)
{

	if ((pte_val(*ptep) & H_PAGE_RW) == 0)
		return;

	hlpte_update(mm, addr, ptep, H_PAGE_RW, 0, 0);
}

static inline void huge_hlptep_set_wrprotect(struct mm_struct *mm,
					   unsigned long addr, pte_t *ptep)
{
	if ((pte_val(*ptep) & H_PAGE_RW) == 0)
		return;

	hlpte_update(mm, addr, ptep, H_PAGE_RW, 0, 1);
}


/* Set the dirty and/or accessed bits atomically in a linux PTE, this
 * function doesn't need to flush the hash entry
 */
static inline void __hlptep_set_access_flags(pte_t *ptep, pte_t entry)
{
	pte_t pte;
	unsigned long old_pte, new_pte;
	unsigned long bits = pte_val(entry) &
		(H_PAGE_DIRTY | H_PAGE_ACCESSED | H_PAGE_RW | H_PAGE_EXEC);


	do {
reload:
		pte = READ_ONCE(*ptep);
		old_pte = pte_val(pte);

		/* If PTE busy, retry */
		if (unlikely(old_pte & H_PAGE_BUSY))
			goto reload;
		/*
		 * Try to lock the PTE, add ACCESSED and DIRTY if it was
		 * a write access. Since this is 4K insert of 64K page size
		 * also add _PAGE_COMBO
		 */
		new_pte = old_pte | bits;

	} while (cpu_to_be64(old_pte) != __cmpxchg_u64((unsigned long *)ptep,
						       cpu_to_be64(old_pte),
						       cpu_to_be64(new_pte)));
}

static inline int hlpgd_bad(pgd_t pgd)
{
	return (pgd_val(pgd) == 0);
}

#define __HAVE_ARCH_PTE_SAME
#define hlpte_same(A,B)	(((pte_val(A) ^ pte_val(B)) & ~H_PAGE_HPTEFLAGS) == 0)
#define hlpgd_page_vaddr(pgd)	(pgd_val(pgd) & ~H_PGD_MASKED_BITS)


/* Generic accessors to PTE bits */
static inline int hlpte_write(pte_t pte)
{
	return !!(pte_val(pte) & H_PAGE_RW);
}

static inline int hlpte_dirty(pte_t pte)
{
	return !!(pte_val(pte) & H_PAGE_DIRTY);
}

static inline int hlpte_young(pte_t pte)
{
	return !!(pte_val(pte) & H_PAGE_ACCESSED);
}

static inline int hlpte_special(pte_t pte)
{
	return !!(pte_val(pte) & H_PAGE_SPECIAL);
}

static inline int hlpte_none(pte_t pte)
{
	return (pte_val(pte) & ~H_PTE_NONE_MASK) == 0;
}

static inline pgprot_t hlpte_pgprot(pte_t pte)
{
	return __pgprot(pte_val(pte) & H_PAGE_PROT_BITS);
}

#ifdef CONFIG_NUMA_BALANCING
/*
 * These work without NUMA balancing but the kernel does not care. See the
 * comment in include/asm-generic/pgtable.h . On powerpc, this will only
 * work for user pages and always return true for kernel pages.
 */
static inline int hlpte_protnone(pte_t pte)
{
	return (pte_val(pte) &
		(H_PAGE_PRESENT | H_PAGE_USER)) == H_PAGE_PRESENT;
}
#endif /* CONFIG_NUMA_BALANCING */

static inline int hlpte_present(pte_t pte)
{
	return pte_val(pte) & H_PAGE_PRESENT;
}

/* Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 *
 * Even if PTEs can be unsigned long long, a PFN is always an unsigned
 * long for now.
 */
static inline pte_t pfn_hlpte(unsigned long pfn, pgprot_t pgprot)
{
	return __pte(((pte_basic_t)(pfn) << H_PTE_RPN_SHIFT) |
		     pgprot_val(pgprot));
}

static inline unsigned long hlpte_pfn(pte_t pte)
{
	return pte_val(pte) >> H_PTE_RPN_SHIFT;
}

/* Generic modifiers for PTE bits */
static inline pte_t hlpte_wrprotect(pte_t pte)
{
	return __pte(pte_val(pte) & ~H_PAGE_RW);
}

static inline pte_t hlpte_mkclean(pte_t pte)
{
	return __pte(pte_val(pte) & ~H_PAGE_DIRTY);
}

static inline pte_t hlpte_mkold(pte_t pte)
{
	return __pte(pte_val(pte) & ~H_PAGE_ACCESSED);
}

static inline pte_t hlpte_mkwrite(pte_t pte)
{
	return __pte(pte_val(pte) | H_PAGE_RW);
}

static inline pte_t hlpte_mkdirty(pte_t pte)
{
	return __pte(pte_val(pte) | H_PAGE_DIRTY);
}

static inline pte_t hlpte_mkyoung(pte_t pte)
{
	return __pte(pte_val(pte) | H_PAGE_ACCESSED);
}

static inline pte_t hlpte_mkspecial(pte_t pte)
{
	return __pte(pte_val(pte) | H_PAGE_SPECIAL);
}

static inline pte_t hlpte_mkhuge(pte_t pte)
{
	return pte;
}

static inline pte_t hlpte_modify(pte_t pte, pgprot_t newprot)
{
	return __pte((pte_val(pte) & H_PAGE_CHG_MASK) | pgprot_val(newprot));
}

/* This low level function performs the actual PTE insertion
 * Setting the PTE depends on the MMU type and other factors. It's
 * an horrible mess that I'm not going to try to clean up now but
 * I'm keeping it in one place rather than spread around
 */
static inline void __set_hlpte_at(struct mm_struct *mm, unsigned long addr,
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

static inline pgprot_t hlpgprot_noncached(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~H_PAGE_CACHE_CTL) |
			H_PAGE_NO_CACHE | H_PAGE_GUARDED);
}

static inline pgprot_t hlpgprot_noncached_wc(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~H_PAGE_CACHE_CTL) |
			H_PAGE_NO_CACHE);
}

static inline pgprot_t hlpgprot_cached(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~H_PAGE_CACHE_CTL) |
			H_PAGE_COHERENT);
}

static inline pgprot_t hlpgprot_cached_wthru(pgprot_t prot)
{
	return __pgprot((pgprot_val(prot) & ~H_PAGE_CACHE_CTL) |
			H_PAGE_COHERENT | H_PAGE_WRITETHRU);
}

static inline pgprot_t hlpgprot_cached_noncoherent(pgprot_t prot)
{
	return __pgprot(pgprot_val(prot) & ~H_PAGE_CACHE_CTL);
}

static inline pgprot_t hlpgprot_writecombine(pgprot_t prot)
{
	return hlpgprot_noncached_wc(prot);
}

extern pgprot_t hlvm_get_page_prot(unsigned long vm_flags);

static inline unsigned long hlpte_io_cache_bits(void)
{
	return H_PAGE_NO_CACHE | H_PAGE_GUARDED;
}

static inline unsigned long gup_hlpte_filter(int write)
{
	unsigned long mask;
	mask = H_PAGE_PRESENT | H_PAGE_USER;
	if (write)
		mask |= H_PAGE_RW;
	return mask;
}

static inline unsigned long ioremap_prot_flags(unsigned long flags)
{
	/* FIXME!! Radix for this ? not needed ? */
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

extern int hlpmdp_set_access_flags(struct vm_area_struct *vma,
                                   unsigned long address, pmd_t *pmdp,
                                   pmd_t entry, int dirty);
extern int hlpmdp_test_and_clear_young(struct vm_area_struct *vma,
                                       unsigned long address, pmd_t *pmdp);
extern pmd_t hlpmdp_huge_get_and_clear(struct mm_struct *mm,
                                       unsigned long addr, pmd_t *pmdp);
extern void hlpmdp_splitting_flush(struct vm_area_struct *vma,
                                   unsigned long address, pmd_t *pmdp);
extern pmd_t hlpmdp_collapse_flush(struct vm_area_struct *vma,
                                   unsigned long address, pmd_t *pmdp);
extern void hlpgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
                                         pgtable_t pgtable);
extern pgtable_t hlpgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp);
extern void hlpmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
                              pmd_t *pmdp);
extern int hlmap_kernel_page(unsigned long ea, unsigned long pa, int flags);
extern void hlpgtable_cache_init(void);
extern void __meminit hlvmemmap_create_mapping(unsigned long start,
					       unsigned long page_size,
					       unsigned long phys);
extern void hlvmemmap_remove_mapping(unsigned long start,
				     unsigned long page_size);
extern void set_hlpte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
			 pte_t pte);
extern void hlupdate_mmu_cache(struct vm_area_struct *vma, unsigned long address,
			       pte_t *ptep);
#endif /* !__ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif /* _ASM_POWERPC_BOOK3S_64_HASH_H */
