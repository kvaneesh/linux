#ifndef _ASM_POWERPC_BOOK3S_64_PGTABLE_H_
#define _ASM_POWERPC_BOOK3S_64_PGTABLE_H_
/*
 * This file contains the functions and defines necessary to modify and use
 * the ppc64 hashed page table.
 */

#define SWP_TYPE_BITS 5
#include <asm/book3s/64/hash.h>
#include <asm/book3s/64/radix.h>
#include <asm/barrier.h>

#ifndef __ASSEMBLY__
#include <asm/tlbflush.h>
#include <linux/mm_types.h>
#endif

/*
 * Radix require pgd to be 64K in size even for 4K page size.
 * Hence default to that always
 */
#define MAX_PGD_TABLE_SIZE  RPGD_TABLE_SIZE
/*
 * The second half of the kernel virtual space is used for IO mappings,
 * it's itself carved into the PIO region (ISA and PHB IO space) and
 * the ioremap space
 *
 *  ISA_IO_BASE = KERN_IO_START, 64K reserved area
 *  PHB_IO_BASE = ISA_IO_BASE + 64K to ISA_IO_BASE + 2G, PHB IO spaces
 * IOREMAP_BASE = ISA_IO_BASE + 2G to VMALLOC_START + PGTABLE_RANGE
 */
#define KERN_IO_START	(KERN_VIRT_START + (KERN_VIRT_SIZE >> 1))
#define FULL_IO_SIZE	0x80000000ul
#define  ISA_IO_BASE	(KERN_IO_START)
#define  ISA_IO_END	(KERN_IO_START + 0x10000ul)
#define  PHB_IO_BASE	(ISA_IO_END)
#define  PHB_IO_END	(KERN_IO_START + FULL_IO_SIZE)
#define IOREMAP_BASE	(PHB_IO_END)
#define IOREMAP_END	(KERN_VIRT_START + KERN_VIRT_SIZE)

/* Advertise special mapping type for AGP */
#define HAVE_PAGE_AGP

/* Advertise support for _PAGE_SPECIAL */
#define __HAVE_ARCH_PTE_SPECIAL

#ifndef __ASSEMBLY__
#ifdef CONFIG_PPC_BOOK3S_64
extern struct page *vmemmap;
extern unsigned long __vmalloc_start;
extern unsigned long __vmalloc_end;
#define VMALLOC_START	__vmalloc_start
#define VMALLOC_END	__vmalloc_end

extern unsigned long __kernel_virt_start;
extern unsigned long __kernel_virt_size;
#define KERN_VIRT_START __kernel_virt_start
#define KERN_VIRT_SIZE  __kernel_virt_size

extern unsigned long __ptrs_per_pte;
#define PTRS_PER_PTE __ptrs_per_pte

extern unsigned long __ptrs_per_pmd;
#define PTRS_PER_PMD __ptrs_per_pmd

extern unsigned long __pmd_shift;
#define PMD_SHIFT	__pmd_shift
#define PMD_SIZE	(1UL << __pmd_shift)
#define PMD_MASK	(~(PMD_SIZE -1 ))

#ifndef __PAGETABLE_PUD_FOLDED
extern unsigned long __pud_shift;
#define PUD_SHIFT	__pud_shift
#define PUD_SIZE	(1UL << __pud_shift)
#define PUD_MASK	(~(PUD_SIZE -1 ))
#endif

extern unsigned long __pgdir_shift;
#define PGDIR_SHIFT	__pgdir_shift
#define PGDIR_SIZE	(1UL << __pgdir_shift)
#define PGDIR_MASK	(~(PGDIR_SIZE -1 ))

extern pgprot_t __kernel_page_prot;
#define PAGE_KERNEL __kernel_page_prot

extern pgprot_t __page_none;
#define PAGE_NONE  __page_none

extern pgprot_t __page_kernel_exec;
#define PAGE_KERNEL_EXEC __page_kernel_exec

extern unsigned long __page_no_cache;
#define _PAGE_NO_CACHE  __page_no_cache

extern unsigned long __page_guarded;
#define _PAGE_GUARDED  __page_guarded

extern unsigned long __page_user;
#define _PAGE_USER __page_user

extern unsigned long __page_coherent;
#define _PAGE_COHERENT __page_coherent

extern unsigned long __page_present;
#define _PAGE_PRESENT __page_present

#endif /* CONFIG_PPC_BOOK3S_64 */
extern unsigned long ioremap_bot;

/*
 * This is the default implementation of various PTE accessors, it's
 * used in all cases except Book3S with 64K pages where we have a
 * concept of sub-pages
 */
#ifndef __real_pte

#ifdef CONFIG_STRICT_MM_TYPECHECKS
#define __real_pte(e,p)		((real_pte_t){(e)})
#define __rpte_to_pte(r)	((r).pte)
#else
#define __real_pte(e,p)		(e)
#define __rpte_to_pte(r)	(__pte(r))
#endif
#define __rpte_to_hidx(r,index)	(pte_val(__rpte_to_pte(r)) >> H_PAGE_F_GIX_SHIFT)

#define pte_iterate_hashed_subpages(rpte, psize, va, index, shift)       \
	do {							         \
		index = 0;					         \
		shift = mmu_psize_defs[psize].shift;		         \

#define pte_iterate_hashed_end() } while(0)

/*
 * We expect this to be called only for user addresses or kernel virtual
 * addresses other than the linear mapping.
 */
#define pte_pagesize_index(mm, addr, pte)	MMU_PAGE_4K

#endif /* __real_pte */

#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
static inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
					    unsigned long address,
					    pte_t *ptep)
{
	if (radix_enabled())
		return  __rptep_test_and_clear_young(vma->vm_mm, address, ptep);
	return  __hlptep_test_and_clear_young(vma->vm_mm, address, ptep);
}

#define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
static inline int ptep_clear_flush_young(struct vm_area_struct *vma,
					 unsigned long address, pte_t *ptep)
{
	int young;

	if (radix_enabled())
		young = __rptep_test_and_clear_young(vma->vm_mm, address, ptep);
	else
		young = __hlptep_test_and_clear_young(vma->vm_mm, address, ptep);
	if (young)
		flush_tlb_page(vma, address);
	return young;
}

#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
				       unsigned long addr, pte_t *ptep)
{
	unsigned long old;

	if (radix_enabled())
		old = rpte_update(mm, addr, ptep, ~0UL, 0, 0);
	else
		old = hlpte_update(mm, addr, ptep, ~0UL, 0, 0);
	return __pte(old);
}

static inline void pte_clear(struct mm_struct *mm, unsigned long addr,
			     pte_t * ptep)
{

	if (radix_enabled())
		rpte_update(mm, addr, ptep, ~0UL, 0, 0);
	else
		hlpte_update(mm, addr, ptep, ~0UL, 0, 0);
}

static inline int pte_index(unsigned long addr)
{
	if (radix_enabled())
		return rpte_index(addr);
	return hlpte_index(addr);
}

static inline unsigned long pte_update(struct mm_struct *mm,
				       unsigned long addr,
				       pte_t *ptep, unsigned long clr,
				       unsigned long set,
				       int huge)
{
	if (radix_enabled())
		return rpte_update(mm, addr, ptep, clr, set, huge);
	return hlpte_update(mm, addr, ptep, clr, set, huge);
}

static inline int __ptep_test_and_clear_young(struct mm_struct *mm,
					      unsigned long addr, pte_t *ptep)
{
	if (radix_enabled())
		return __rptep_test_and_clear_young(mm, addr, ptep);
	return __hlptep_test_and_clear_young(mm, addr, ptep);

}

#define __HAVE_ARCH_PTEP_SET_WRPROTECT
static inline void ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr,
				      pte_t *ptep)
{
	if (radix_enabled())
		return rptep_set_wrprotect(mm, addr, ptep);
	return hlptep_set_wrprotect(mm, addr, ptep);
}

static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
					   unsigned long addr, pte_t *ptep)
{
	if (radix_enabled())
		return huge_rptep_set_wrprotect(mm, addr, ptep);
	return huge_hlptep_set_wrprotect(mm, addr, ptep);
}


/* Set the dirty and/or accessed bits atomically in a linux PTE, this
 * function doesn't need to flush the hash entry
 */
static inline void __ptep_set_access_flags(pte_t *ptep, pte_t entry)
{
	if (radix_enabled())
		return __rptep_set_access_flags(ptep, entry);
	return __hlptep_set_access_flags(ptep, entry);
}

#define __HAVE_ARCH_PTE_SAME
static inline int pte_same(pte_t pte_a, pte_t pte_b)
{
	if (radix_enabled())
		return rpte_same(pte_a, pte_b);
	return hlpte_same(pte_a, pte_b);
}

static inline int pte_write(pte_t pte)
{
	if (radix_enabled())
		return rpte_write(pte);
	return hlpte_write(pte);
}

static inline int pte_dirty(pte_t pte)
{
	if (radix_enabled())
		return rpte_dirty(pte);
	return hlpte_dirty(pte);
}

static inline int pte_young(pte_t pte)
{
	if (radix_enabled())
		return rpte_young(pte);
	return hlpte_young(pte);
}

static inline int pte_special(pte_t pte)
{
	if (radix_enabled())
		return rpte_special(pte);
	return hlpte_special(pte);
}

static inline int pte_none(pte_t pte)
{
	if (radix_enabled())
		return rpte_none(pte);
	return hlpte_none(pte);
}

static inline pgprot_t pte_pgprot(pte_t pte)
{
	if (radix_enabled())
		return rpte_pgprot(pte);
	return hlpte_pgprot(pte);
}

static inline pte_t pfn_pte(unsigned long pfn, pgprot_t pgprot)
{
	if (radix_enabled())
		return pfn_rpte(pfn, pgprot);
	return pfn_hlpte(pfn, pgprot);
}

static inline unsigned long pte_pfn(pte_t pte)
{
	if (radix_enabled())
		return rpte_pfn(pte);
	return hlpte_pfn(pte);
}

static inline pte_t pte_wrprotect(pte_t pte)
{
	if (radix_enabled())
		return rpte_wrprotect(pte);
	return hlpte_wrprotect(pte);
}

static inline pte_t pte_mkclean(pte_t pte)
{
	if (radix_enabled())
		return rpte_mkclean(pte);
	return hlpte_mkclean(pte);
}

static inline pte_t pte_mkold(pte_t pte)
{
	if (radix_enabled())
		return rpte_mkold(pte);
	return hlpte_mkold(pte);
}

static inline pte_t pte_mkwrite(pte_t pte)
{
	if (radix_enabled())
		return rpte_mkwrite(pte);
	return hlpte_mkwrite(pte);
}

static inline pte_t pte_mkdirty(pte_t pte)
{
	if (radix_enabled())
		return rpte_mkdirty(pte);
	return hlpte_mkdirty(pte);
}

static inline pte_t pte_mkyoung(pte_t pte)
{
	if (radix_enabled())
		return rpte_mkyoung(pte);
	return hlpte_mkyoung(pte);
}

static inline pte_t pte_mkspecial(pte_t pte)
{
	if (radix_enabled())
		return rpte_mkspecial(pte);
	return hlpte_mkspecial(pte);
}

static inline pte_t pte_mkhuge(pte_t pte)
{
	if (radix_enabled())
		return rpte_mkhuge(pte);
	return hlpte_mkhuge(pte);
}

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	if (radix_enabled())
		return rpte_modify(pte, newprot);
	return hlpte_modify(pte, newprot);
}

static inline void __set_pte_at(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep, pte_t pte, int percpu)
{
	if (radix_enabled())
		return __set_rpte_at(mm, addr, ptep, pte, percpu);
	return __set_hlpte_at(mm, addr, ptep, pte, percpu);
}

#ifdef CONFIG_NUMA_BALANCING
static inline int pte_protnone(pte_t pte)
{
	if (radix_enabled())
		return rpte_protnone(pte);
	return hlpte_protnone(pte);
}
#endif /* CONFIG_NUMA_BALANCING */

static inline int pte_present(pte_t pte)
{
	if (radix_enabled())
		return rpte_present(pte);
	return hlpte_present(pte);
}

static inline void set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte)
{
	if (radix_enabled())
		return set_rpte_at(mm, addr, ptep, pte);
	return set_hlpte_at(mm, addr, ptep, pte);
}
/*
 * Swap definitions
 */

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
#define __pte_to_swp_entry(pte)		((swp_entry_t) { pte_val((pte)) })
#define __swp_entry_to_pte(x)		__pte((x).val)
static inline unsigned long __swp_type(swp_entry_t entry)
{
	if (radix_enabled())
		return r_swp_type(entry);
	return hl_swp_type(entry);
}

static inline pgoff_t __swp_offset(swp_entry_t entry)
{
	if (radix_enabled())
		return r_swp_offset(entry);
	return hl_swp_offset(entry);
}

static inline swp_entry_t __swp_entry(unsigned long type, pgoff_t offset)
{
	if (radix_enabled())
		return r_swp_entry(type, offset);
	return hl_swp_entry(type, offset);
}

static inline void pmd_set(pmd_t *pmdp, unsigned long val)
{
	*pmdp = __pmd(val);
}

static inline void pmd_clear(pmd_t *pmdp)
{
	*pmdp = __pmd(0);
}

static inline int pmd_bad(pmd_t pmd)
{
	if (radix_enabled())
		return rpmd_bad(pmd);
	return hlpmd_bad(pmd);
}

static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	if (radix_enabled())
		return rpmd_page_vaddr(pmd);
	return hlpmd_page_vaddr(pmd);
}

static inline int pmd_index(unsigned long addr)
{
	if (radix_enabled())
		return rpmd_index(addr);
	return hlpmd_index(addr);
}


#define pmd_none(pmd)		(!pmd_val(pmd))
#define	pmd_present(pmd)	(!pmd_none(pmd))

static inline void pud_set(pud_t *pudp, unsigned long val)
{
	*pudp = __pud(val);
}

static inline void pud_clear(pud_t *pudp)
{
	*pudp = __pud(0);
}

#define pud_none(pud)		(!pud_val(pud))
#define pud_present(pud)	(pud_val(pud) != 0)

extern struct page *pud_page(pud_t pud);
extern struct page *pmd_page(pmd_t pmd);
static inline pte_t pud_pte(pud_t pud)
{
	return __pte(pud_val(pud));
}

static inline pud_t pte_pud(pte_t pte)
{
	return __pud(pte_val(pte));
}

static inline int pud_bad(pud_t pud)
{
	if (radix_enabled())
		return rpud_bad(pud);
	return hlpud_bad(pud);
}

static inline unsigned long pud_page_vaddr(pud_t pud)
{
	if (radix_enabled())
		return rpud_page_vaddr(pud);
	return hlpud_page_vaddr(pud);
}

static inline int pud_index(unsigned long addr)
{
	if (radix_enabled())
		return rpud_index(addr);
	return hlpud_index(addr);
}

#define pud_write(pud)		pte_write(pud_pte(pud))
#define pgd_write(pgd)		pte_write(pgd_pte(pgd))
static inline void pgd_set(pgd_t *pgdp, unsigned long val)
{
	*pgdp = __pgd(val);
}

static inline void pgd_clear(pgd_t *pgdp)
{
	*pgdp = __pgd(0);
}

#define pgd_none(pgd)		(!pgd_val(pgd))
#define pgd_present(pgd)	(!pgd_none(pgd))

static inline pte_t pgd_pte(pgd_t pgd)
{
	return __pte(pgd_val(pgd));
}

static inline pgd_t pte_pgd(pte_t pte)
{
	return __pgd(pte_val(pte));
}

static inline int pgd_bad(pgd_t pgd)
{
	if (radix_enabled())
		return rpgd_bad(pgd);
	return hlpgd_bad(pgd);
}

static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	if (radix_enabled())
		return rpgd_page_vaddr(pgd);
	return hlpgd_page_vaddr(pgd);
}

static inline int pgd_index(unsigned long addr)
{
	if (radix_enabled())
		return rpgd_index(addr);
	return hlpgd_index(addr);
}

extern struct page *pgd_page(pgd_t pgd);

/*
 * Find an entry in a page-table-directory.  We combine the address region
 * (the high order N bits) and the pgd portion of the address.
 */

#define pgd_offset(mm, address)	 ((mm)->pgd + pgd_index(address))

#define pud_offset(pgdp, addr)	\
	(((pud_t *) pgd_page_vaddr(*(pgdp))) + pud_index(addr))
#define pmd_offset(pudp,addr) \
	(((pmd_t *) pud_page_vaddr(*(pudp))) + pmd_index(addr))
#define pte_offset_kernel(dir,addr) \
	(((pte_t *) pmd_page_vaddr(*(dir))) + pte_index(addr))

#define pte_offset_map(dir,addr)	pte_offset_kernel((dir), (addr))
#define pte_unmap(pte)			do { } while(0)

/* to find an entry in a kernel page-table-directory */
/* This now only contains the vmalloc pages */
#define pgd_offset_k(address) pgd_offset(&init_mm, address)

#define pte_ERROR(e) \
	pr_err("%s:%d: bad pte %08lx.\n", __FILE__, __LINE__, pte_val(e))
#define pmd_ERROR(e) \
	pr_err("%s:%d: bad pmd %08lx.\n", __FILE__, __LINE__, pmd_val(e))
#define pud_ERROR(e) \
	pr_err("%s:%d: bad pud %08lx.\n", __FILE__, __LINE__, pud_val(e))
#define pgd_ERROR(e) \
	pr_err("%s:%d: bad pgd %08lx.\n", __FILE__, __LINE__, pgd_val(e))

void pgtable_cache_add(unsigned shift, void (*ctor)(void *));
static inline void pgtable_cache_init(void)
{
	if (radix_enabled())
		return rpgtable_cache_init();
	return hlpgtable_cache_init();
}

static inline int map_kernel_page(unsigned long ea, unsigned long pa,
				  unsigned long flags)
{
	if (radix_enabled()) {
#if defined(CONFIG_PPC_RADIX_MMU) && defined(DEBUG_VM)
		unsigned long page_size = 1 << mmu_psize_defs[mmu_io_psize].shift;
		WARN((page_size != PAGE_SIZE), "I/O page size != PAGE_SIZE");
#endif
		return map_radix_kernel_page(ea, pa, __pgprot(flags), PAGE_SIZE);
	}
	return hlmap_kernel_page(ea, pa, flags);
}

static inline void __meminit vmemmap_create_mapping(unsigned long start,
						    unsigned long page_size,
						    unsigned long phys)
{
	return hlvmemmap_create_mapping(start, page_size, phys);
}

#ifdef CONFIG_MEMORY_HOTPLUG
static inline void vmemmap_remove_mapping(unsigned long start,
					  unsigned long page_size)
{
	return hlvmemmap_remove_mapping(start, page_size);
}
#endif

/*
 * This gets called at the end of handling a page fault, when
 * the kernel has put a new PTE into the page table for the process.
 * We use it to ensure coherency between the i-cache and d-cache
 * for the page which has just been mapped in.
 * On machines which use an MMU hash table, we use this to put a
 * corresponding HPTE into the hash table ahead of time, instead of
 * waiting for the inevitable extra hash-table miss exception.
 */
static inline void update_mmu_cache(struct vm_area_struct *vma, unsigned long address,
				    pte_t *ptep)
{
	if (radix_enabled())
		return;
	return hlupdate_mmu_cache(vma, address, ptep);
}

struct page *realmode_pfn_to_page(unsigned long pfn);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
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
static inline int pmd_trans_huge(pmd_t pmd)
{
	return hlpmd_trans_huge(pmd);
}

static inline int pmd_trans_splitting(pmd_t pmd)
{
	return hlpmd_trans_splitting(pmd);
}

static inline pmd_t pfn_pmd(unsigned long pfn, pgprot_t pgprot)
{
	return pfn_hlpmd(pfn, pgprot);
}

static inline pmd_t mk_pmd(struct page *page, pgprot_t pgprot)
{
	return mk_hlpmd(page, pgprot);
}

static inline pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{
	return hlpmd_modify(pmd, newprot);
}
/*
 * This is called at the end of handling a user page fault, when the
 * fault has been handled by updating a HUGE PMD entry in the linux page tables.
 * We use it to preload an HPTE into the hash table corresponding to
 * the updated linux HUGE PMD entry.
 */
static inline void update_mmu_cache_pmd(struct vm_area_struct *vma,
					unsigned long addr, pmd_t *pmd)
{
	return;
}

static inline int has_transparent_hugepage(void)
{
	return hl_has_transparent_hugepage();
}

static inline void set_pmd_at(struct mm_struct *mm, unsigned long addr,
			      pmd_t *pmdp, pmd_t pmd)
{
	return set_hlpmd_at(mm, addr, pmdp, pmd);
}

static inline int pmd_large(pmd_t pmd)
{
	return hlpmd_large(pmd);
}

static inline pmd_t pmd_mknotpresent(pmd_t pmd)
{
	return hlpmd_mknotpresent(pmd);
}

static inline pmd_t pmd_mksplitting(pmd_t pmd)
{
	return hlpmd_mksplitting(pmd);
}

static inline pmd_t pmd_mkhuge(pmd_t pmd)
{
	return hlpmd_mkhuge(pmd);
}

#define __HAVE_ARCH_PMD_SAME
static inline int pmd_same(pmd_t pmd_a, pmd_t pmd_b)
{
	if (radix_enabled())
		return rpmd_same(pmd_a, pmd_b);
	return hlpmd_same(pmd_a, pmd_b);
}

static inline int __pmdp_test_and_clear_young(struct mm_struct *mm,
					      unsigned long addr, pmd_t *pmdp)
{
	return __hlpmdp_test_and_clear_young(mm, addr, pmdp);
}

#define __HAVE_ARCH_PMDP_SET_WRPROTECT
static inline void pmdp_set_wrprotect(struct mm_struct *mm, unsigned long addr,
				      pmd_t *pmdp)
{
	return hlpmdp_set_wrprotect(mm, addr, pmdp);
}

#endif /* CONFIG_TRANSPARENT_HUGEPAGE */


static inline pte_t pmd_pte(pmd_t pmd)
{
	return __pte(pmd_val(pmd));
}

static inline pmd_t pte_pmd(pte_t pte)
{
	return __pmd(pte_val(pte));
}

static inline pte_t *pmdp_ptep(pmd_t *pmd)
{
	return (pte_t *)pmd;
}

#define pmd_pfn(pmd)		pte_pfn(pmd_pte(pmd))
#define pmd_dirty(pmd)		pte_dirty(pmd_pte(pmd))
#define pmd_young(pmd)		pte_young(pmd_pte(pmd))
#define pmd_mkold(pmd)		pte_pmd(pte_mkold(pmd_pte(pmd)))
#define pmd_wrprotect(pmd)	pte_pmd(pte_wrprotect(pmd_pte(pmd)))
#define pmd_mkdirty(pmd)	pte_pmd(pte_mkdirty(pmd_pte(pmd)))
#define pmd_mkyoung(pmd)	pte_pmd(pte_mkyoung(pmd_pte(pmd)))
#define pmd_mkwrite(pmd)	pte_pmd(pte_mkwrite(pmd_pte(pmd)))
#ifdef CONFIG_NUMA_BALANCING
static inline int pmd_protnone(pmd_t pmd)
{
	return pte_protnone(pmd_pte(pmd));
}
#endif /* CONFIG_NUMA_BALANCING */

#define __HAVE_ARCH_PMD_WRITE
#define pmd_write(pmd)		pte_write(pmd_pte(pmd))

#define __HAVE_ARCH_PMDP_SET_ACCESS_FLAGS
static inline int pmdp_set_access_flags(struct vm_area_struct *vma,
					unsigned long address, pmd_t *pmdp,
					pmd_t entry, int dirty)
{
	return hlpmdp_set_access_flags(vma, address, pmdp, entry, dirty);
}

#define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
static inline int pmdp_test_and_clear_young(struct vm_area_struct *vma,
					    unsigned long address, pmd_t *pmdp)
{
	return hlpmdp_test_and_clear_young(vma, address, pmdp);
}


#define __HAVE_ARCH_PMDP_HUGE_GET_AND_CLEAR
static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
					    unsigned long addr, pmd_t *pmdp)
{
	return hlpmdp_huge_get_and_clear(mm, addr, pmdp);
}

#define __HAVE_ARCH_PMDP_SPLITTING_FLUSH
static inline void pmdp_splitting_flush(struct vm_area_struct *vma,
					unsigned long address, pmd_t *pmdp)
{
	return hlpmdp_splitting_flush(vma, address, pmdp);
}

static inline pmd_t pmdp_collapse_flush(struct vm_area_struct *vma,
					unsigned long address, pmd_t *pmdp)
{
	return hlpmdp_collapse_flush(vma, address, pmdp);
}
#define pmdp_collapse_flush pmdp_collapse_flush

#define __HAVE_ARCH_PGTABLE_DEPOSIT
static inline void pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
					      pgtable_t pgtable)
{
	return hlpgtable_trans_huge_deposit(mm, pmdp, pgtable);
}

#define __HAVE_ARCH_PGTABLE_WITHDRAW
static inline pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp)
{
	return hlpgtable_trans_huge_withdraw(mm, pmdp);
}

#define __HAVE_ARCH_PMDP_INVALIDATE
static inline void pmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
				   pmd_t *pmdp)
{
	return hlpmdp_invalidate(vma, address, pmdp);
}

#define pmd_move_must_withdraw pmd_move_must_withdraw
struct spinlock;
static inline int pmd_move_must_withdraw(struct spinlock *new_pmd_ptl,
					 struct spinlock *old_pmd_ptl)
{
	/*
	 * Archs like ppc64 use pgtable to store per pmd
	 * specific information. So when we switch the pmd,
	 * we should also withdraw and deposit the pgtable
	 */
	return true;
}

#ifdef CONFIG_HUGETLB_PAGE

static inline int pmd_huge(pmd_t pmd)
{
	return hlpmd_huge(pmd);
}

static inline int pud_huge(pud_t pud)
{
	return hlpud_huge(pud);
}

static inline int pgd_huge(pgd_t pgd)
{
	return hlpgd_huge(pgd);
}

static inline bool hugepd_ok(hugepd_t hpd)
{
	return hlhugepd_ok(hpd);
}

static inline bool is_hugepd(hugepd_t hpd)
{
	return is_hlhugepd(hpd);
}
#define is_hugepd is_hugepd

#endif /* CONFIG_HUGETLB_PAGE */

#define pgprot_noncached pgprot_noncached
static inline pgprot_t pgprot_noncached(pgprot_t prot)
{
	if (radix_enabled())
		return rpgprot_noncached(prot);
	return hlpgprot_noncached(prot);
}

#define pgprot_noncached_wc pgprot_noncached_wc
static inline pgprot_t pgprot_noncached_wc(pgprot_t prot)
{
	if (radix_enabled())
		return rpgprot_noncached_wc(prot);
	return hlpgprot_noncached_wc(prot);
}

#define pgprot_cached pgprot_cached
static inline pgprot_t pgprot_cached(pgprot_t prot)
{
	if (radix_enabled())
		return rpgprot_cached(prot);
	return hlpgprot_cached(prot);
}

#define pgprot_cached_wthru pgprot_cached_wthru
static inline pgprot_t pgprot_cached_wthru(pgprot_t prot)
{
	if (radix_enabled())
		return rpgprot_cached_wthru(prot);
	return hlpgprot_cached_wthru(prot);
}

#define pgprot_cached_noncoherent pgprot_cached_noncoherent
static inline pgprot_t pgprot_cached_noncoherent(pgprot_t prot)
{
	if (radix_enabled())
		return rpgprot_cached_noncoherent(prot);
	return hlpgprot_cached_noncoherent(prot);
}

#define pgprot_writecombine pgprot_writecombine
static inline pgprot_t pgprot_writecombine(pgprot_t prot)
{
	if (radix_enabled())
		return rpgprot_writecombine(prot);
	return hlpgprot_writecombine(prot);
}

/* We want to override core implemntation of this for book3s 64 */
#define vm_get_page_prot vm_get_page_prot
static inline pgprot_t vm_get_page_prot(unsigned long vm_flags)
{
	if (radix_enabled())
		return rvm_get_page_prot(vm_flags);
	return hlvm_get_page_prot(vm_flags);
}

static inline unsigned long pte_io_cache_bits(void)
{
	if (radix_enabled())
		return rpte_io_cache_bits();
	return hlpte_io_cache_bits();
}

static inline unsigned long gup_pte_filter(int write)
{
	if (radix_enabled())
		return gup_rpte_filter(write);
	return gup_hlpte_filter(write);
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_POWERPC_BOOK3S_64_PGTABLE_H_ */
