/*
 * This file contains common routines for dealing with free of page tables
 * Along with common page table handling code
 *
 *  Derived from arch/powerpc/mm/tlb_64.c:
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 *  Modifications by Paul Mackerras (PowerMac) (paulus@cs.anu.edu.au)
 *  and Cort Dougan (PReP) (cort@cs.nmt.edu)
 *    Copyright (C) 1996 Paul Mackerras
 *
 *  Derived from "arch/i386/mm/init.c"
 *    Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Dave Engebretsen <engebret@us.ibm.com>
 *      Rework for PPC64 port.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/hugetlb.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include <asm/machdep.h>

#include "mmu_decl.h"

static inline int is_exec_fault(void)
{
	return current->thread.regs && TRAP(current->thread.regs) == 0x400;
}

/* We only try to do i/d cache coherency on stuff that looks like
 * reasonably "normal" PTEs. We currently require a PTE to be present
 * and we avoid _PAGE_SPECIAL and _PAGE_NO_CACHE. We also only do that
 * on userspace PTEs
 */
static inline int pte_looks_normal(pte_t pte)
{
	return (pte_val(pte) &
	    (_PAGE_PRESENT | _PAGE_SPECIAL | _PAGE_NO_CACHE | _PAGE_USER)) ==
	    (_PAGE_PRESENT | _PAGE_USER);
}

struct page * maybe_pte_to_page(pte_t pte)
{
	unsigned long pfn = pte_pfn(pte);
	struct page *page;

	if (unlikely(!pfn_valid(pfn)))
		return NULL;
	page = pfn_to_page(pfn);
	if (PageReserved(page))
		return NULL;
	return page;
}

#if defined(CONFIG_PPC_STD_MMU) || _PAGE_EXEC == 0

/* Server-style MMU handles coherency when hashing if HW exec permission
 * is supposed per page (currently 64-bit only). If not, then, we always
 * flush the cache for valid PTEs in set_pte. Embedded CPU without HW exec
 * support falls into the same category.
 */

static pte_t set_pte_filter(pte_t pte, unsigned long addr)
{
	pte = __pte(pte_val(pte) & ~_PAGE_HPTEFLAGS);
	if (pte_looks_normal(pte) && !(cpu_has_feature(CPU_FTR_COHERENT_ICACHE) ||
				       cpu_has_feature(CPU_FTR_NOEXECUTE))) {
		struct page *pg = maybe_pte_to_page(pte);
		if (!pg)
			return pte;
		if (!test_bit(PG_arch_1, &pg->flags)) {
#ifdef CONFIG_8xx
			/* On 8xx, cache control instructions (particularly
			 * "dcbst" from flush_dcache_icache) fault as write
			 * operation if there is an unpopulated TLB entry
			 * for the address in question. To workaround that,
			 * we invalidate the TLB here, thus avoiding dcbst
			 * misbehaviour.
			 */
			/* 8xx doesn't care about PID, size or ind args */
			_tlbil_va(addr, 0, 0, 0);
#endif /* CONFIG_8xx */
			flush_dcache_icache_page(pg);
			set_bit(PG_arch_1, &pg->flags);
		}
	}
	return pte;
}

static pte_t set_access_flags_filter(pte_t pte, struct vm_area_struct *vma,
				     int dirty)
{
	return pte;
}

#else /* defined(CONFIG_PPC_STD_MMU) || _PAGE_EXEC == 0 */

/* Embedded type MMU with HW exec support. This is a bit more complicated
 * as we don't have two bits to spare for _PAGE_EXEC and _PAGE_HWEXEC so
 * instead we "filter out" the exec permission for non clean pages.
 */
static pte_t set_pte_filter(pte_t pte, unsigned long addr)
{
	struct page *pg;

	/* No exec permission in the first place, move on */
	if (!(pte_val(pte) & _PAGE_EXEC) || !pte_looks_normal(pte))
		return pte;

	/* If you set _PAGE_EXEC on weird pages you're on your own */
	pg = maybe_pte_to_page(pte);
	if (unlikely(!pg))
		return pte;

	/* If the page clean, we move on */
	if (test_bit(PG_arch_1, &pg->flags))
		return pte;

	/* If it's an exec fault, we flush the cache and make it clean */
	if (is_exec_fault()) {
		flush_dcache_icache_page(pg);
		set_bit(PG_arch_1, &pg->flags);
		return pte;
	}

	/* Else, we filter out _PAGE_EXEC */
	return __pte(pte_val(pte) & ~_PAGE_EXEC);
}

static pte_t set_access_flags_filter(pte_t pte, struct vm_area_struct *vma,
				     int dirty)
{
	struct page *pg;

	/* So here, we only care about exec faults, as we use them
	 * to recover lost _PAGE_EXEC and perform I$/D$ coherency
	 * if necessary. Also if _PAGE_EXEC is already set, same deal,
	 * we just bail out
	 */
	if (dirty || (pte_val(pte) & _PAGE_EXEC) || !is_exec_fault())
		return pte;

#ifdef CONFIG_DEBUG_VM
	/* So this is an exec fault, _PAGE_EXEC is not set. If it was
	 * an error we would have bailed out earlier in do_page_fault()
	 * but let's make sure of it
	 */
	if (WARN_ON(!(vma->vm_flags & VM_EXEC)))
		return pte;
#endif /* CONFIG_DEBUG_VM */

	/* If you set _PAGE_EXEC on weird pages you're on your own */
	pg = maybe_pte_to_page(pte);
	if (unlikely(!pg))
		goto bail;

	/* If the page is already clean, we move on */
	if (test_bit(PG_arch_1, &pg->flags))
		goto bail;

	/* Clean the page and set PG_arch_1 */
	flush_dcache_icache_page(pg);
	set_bit(PG_arch_1, &pg->flags);

 bail:
	return __pte(pte_val(pte) | _PAGE_EXEC);
}

#endif /* !(defined(CONFIG_PPC_STD_MMU) || _PAGE_EXEC == 0) */

/*
 * set_pte stores a linux PTE into the linux page table.
 */
void set_pte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
		pte_t pte)
{
#ifdef CONFIG_DEBUG_VM
	WARN_ON(pte_present(*ptep));
#endif
	/* Note: mm->context.id might not yet have been assigned as
	 * this context might not have been activated yet when this
	 * is called.
	 */
	pte = set_pte_filter(pte, addr);

	/* Perform the setting of the PTE */
	__set_pte_at(mm, addr, ptep, pte, 0);
}

/*
 * This is called when relaxing access to a PTE. It's also called in the page
 * fault path when we don't hit any of the major fault cases, ie, a minor
 * update of _PAGE_ACCESSED, _PAGE_DIRTY, etc... The generic code will have
 * handled those two for us, we additionally deal with missing execute
 * permission here on some processors
 */
int ptep_set_access_flags(struct vm_area_struct *vma, unsigned long address,
			  pte_t *ptep, pte_t entry, int dirty)
{
	int changed;
	entry = set_access_flags_filter(entry, vma, dirty);
	changed = !pte_same(*(ptep), entry);
	if (changed) {
		if (!is_vm_hugetlb_page(vma))
			assert_pte_locked(vma->vm_mm, address);
		__ptep_set_access_flags(ptep, entry);
		flush_tlb_page_nohash(vma, address);
	}
	return changed;
}

#ifdef CONFIG_DEBUG_VM
void assert_pte_locked(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	if (mm == &init_mm)
		return;
	pgd = mm->pgd + pgd_index(addr);
	BUG_ON(pgd_none(*pgd));
	pud = pud_offset(pgd, addr);
	BUG_ON(pud_none(*pud));
	pmd = pmd_offset(pud, addr);
	BUG_ON(!pmd_present(*pmd));
	assert_spin_locked(pte_lockptr(mm, pmd));
}
#endif /* CONFIG_DEBUG_VM */


#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static pmd_t set_hugepage_access_flags_filter(pmd_t pmd,
					      struct vm_area_struct *vma,
					      int dirty)
{
	return pmd;
}

/*
 * This is called when relaxing access to a hugepage. It's also called in the page
 * fault path when we don't hit any of the major fault cases, ie, a minor
 * update of _PAGE_ACCESSED, _PAGE_DIRTY, etc... The generic code will have
 * handled those two for us, we additionally deal with missing execute
 * permission here on some processors
 */
int pmdp_set_access_flags(struct vm_area_struct *vma, unsigned long address,
			  pmd_t *pmdp, pmd_t entry, int dirty)
{
	int changed;
	entry = set_hugepage_access_flags_filter(entry, vma, dirty);
	changed = !pmd_same(*(pmdp), entry);
	if (changed) {
		__pmdp_set_access_flags(pmdp, entry);
		/*
		 * Since we are not supporting SW TLB systems, we don't
		 * have any thing similar to flush_tlb_page_nohash()
		 */
	}
	return changed;
}

int pmdp_test_and_clear_young(struct vm_area_struct *vma,
			      unsigned long address, pmd_t *pmdp)
{
	return __pmdp_test_and_clear_young(vma->vm_mm, address, pmdp);
}

/*
 * We currently remove entries from the hashtable regardless of whether
 * the entry was young or dirty. The generic routines only flush if the
 * entry was young or dirty which is not good enough.
 *
 * We should be more intelligent about this but for the moment we override
 * these functions and force a tlb flush unconditionally
 */
int pmdp_clear_flush_young(struct vm_area_struct *vma,
				  unsigned long address, pmd_t *pmdp)
{
	return __pmdp_test_and_clear_young(vma->vm_mm, address, pmdp);
}

/*
 * We mark the pmd splitting and invalidate all the hpte
 * entries for this hugepage.
 */
void pmdp_splitting_flush(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp)
{
	unsigned long old, tmp;

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
#ifdef PTE_ATOMIC_UPDATES

	__asm__ __volatile__(
	"1:	ldarx	%0,0,%3\n\
		andi.	%1,%0,%6\n\
		bne-	1b \n\
		ori	%1,%0,%4 \n\
		stdcx.	%1,0,%3 \n\
		bne-	1b"
	: "=&r" (old), "=&r" (tmp), "=m" (*pmdp)
	: "r" (pmdp), "i" (PMD_HUGE_SPLITTING), "m" (*pmdp), "i" (PMD_HUGE_BUSY)
	: "cc" );
#else
	old = pmd_val(*pmdp);
	*pmdp = __pmd(old | PMD_HUGE_SPLITTING);
#endif
	/*
	 * If we didn't had the splitting flag set, go and flush the
	 * HPTE entries and serialize against gup fast.
	 */
	if (!(old & PMD_HUGE_SPLITTING)) {
#ifdef CONFIG_PPC_STD_MMU_64
		/* We need to flush the hpte */
		if (old & PMD_HUGE_HASHPTE)
			hpte_need_hugepage_flush(vma->vm_mm, address, pmdp);
#endif
		/* need tlb flush only to serialize against gup-fast */
		flush_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
	}
}

/*
 * We want to put the pgtable in pmd and use pgtable for tracking
 * the base page size hptes
 */
void pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				pgtable_t pgtable)
{
	unsigned long *pgtable_slot;
	assert_spin_locked(&mm->page_table_lock);
	/*
	 * we store the pgtable in the second half of PMD
	 */
	pgtable_slot = pmdp + PTRS_PER_PMD;
	*pgtable_slot = (unsigned long)pgtable;
}

#define PTE_FRAG_SIZE (2 * PTRS_PER_PTE * sizeof(pte_t))
pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp)
{
	pgtable_t pgtable;
	unsigned long *pgtable_slot;

	assert_spin_locked(&mm->page_table_lock);
	pgtable_slot = pmdp + PTRS_PER_PMD;
	pgtable = (pgtable_t) *pgtable_slot;
	/*
	 * We store HPTE information in the deposited PTE fragment.
	 * zero out the content on withdraw.
	 */
	memset(pgtable, 0, PTE_FRAG_SIZE);
	return pgtable;
}

/*
 * Since we are looking at latest ppc64, we don't need to worry about
 * i/d cache coherency on exec fault
 */
static pmd_t set_pmd_filter(pmd_t pmd, unsigned long addr)
{
	pmd = __pmd(pmd_val(pmd) & ~PMD_HUGE_HPTEFLAGS);
	return pmd;
}

/*
 * We can make it less convoluted than __set_pte_at, because
 * we can ignore lot of hardware here, because this is only for
 * MPSS
 */
static inline void __set_pmd_at(struct mm_struct *mm, unsigned long addr,
				pmd_t *pmdp, pmd_t pmd, int percpu)
{
	/*
	 * There is nothing in hash page table now, so nothing to
	 * invalidate, set_pte_at is used for adding new entry.
	 * For updating we should use update_hugepage_pmd()
	 */
	*pmdp = pmd;
}

/*
 * set a new huge pmd. We should not be called for updating
 * an existing pmd entry. That should go via pmd_hugepage_update.
 */
void set_pmd_at(struct mm_struct *mm, unsigned long addr,
		pmd_t *pmdp, pmd_t pmd)
{
	/*
	 * Note: mm->context.id might not yet have been assigned as
	 * this context might not have been activated yet when this
	 * is called.
	 */
	pmd = set_pmd_filter(pmd, addr);

	__set_pmd_at(mm, addr, pmdp, pmd, 0);

}

void pmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
		     pmd_t *pmdp)
{
	pmd_hugepage_update(vma->vm_mm, address, pmdp, PMD_HUGE_PRESENT);
	flush_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
}

/*
 * A linux hugepage PMD was changed and the corresponding hash table entry
 * neesd to be flushed.
 *
 * The linux hugepage PMD now include the pmd entries followed by the address
 * to the stashed pgtable_t. The stashed pgtable_t contains the hpte bits.
 * [ secondary group | 3 bit hidx | valid ]. We use one byte per each HPTE entry.
 * With 16MB hugepage and 64K HPTE we need 256 entries and with 4K HPTE we need
 * 4096 entries. Both will fit in a 4K pgtable_t.
 */
void hpte_need_hugepage_flush(struct mm_struct *mm, unsigned long addr,
			      pmd_t *pmdp)
{
	int ssize, i;
	unsigned long s_addr;
	unsigned int psize, valid;
	unsigned char *hpte_slot_array;
	unsigned long hidx, vpn, vsid, hash, shift, slot;

	/*
	 * Flush all the hptes mapping this hugepage
	 */
	s_addr = addr & HUGE_PAGE_MASK;
	/*
	 * The hpte hindex are stored in the pgtable whose address is in the
	 * second half of the PMD
	 */
	hpte_slot_array = *(char **)(pmdp + PTRS_PER_PMD);

	/* get the base page size */
	psize = get_slice_psize(mm, s_addr);
	shift = mmu_psize_defs[psize].shift;

	for (i = 0; i < HUGE_PAGE_SIZE/(1ul << shift); i++) {
		/*
		 * 8 bits per each hpte entries
		 * 000| [ secondary group (one bit) | hidx (3 bits) | valid bit]
		 */
		valid = hpte_slot_array[i] & 0x1;
		if (!valid)
			continue;
		hidx =  hpte_slot_array[i]  >> 1;

		/* get the vpn */
		addr = s_addr + (i * (1ul << shift));
		if (!is_kernel_addr(addr)) {
			ssize = user_segment_size(addr);
			vsid = get_vsid(mm->context.id, addr, ssize);
			WARN_ON(vsid == 0);
		} else {
			vsid = get_kernel_vsid(addr, mmu_kernel_ssize);
			ssize = mmu_kernel_ssize;
		}

		vpn = hpt_vpn(addr, vsid, ssize);
		hash = hpt_hash(vpn, shift, ssize);
		if (hidx & _PTEIDX_SECONDARY)
			hash = ~hash;

		slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
		slot += hidx & _PTEIDX_GROUP_IX;
		ppc_md.hpte_invalidate(slot, vpn, psize, ssize, 0);
	}
}

static pmd_t pmd_set_protbits(pmd_t pmd, pgprot_t pgprot)
{
	unsigned long pmd_prot = 0;
	unsigned long prot = pgprot_val(pgprot);

	if (prot & _PAGE_PRESENT)
		pmd_prot |= PMD_HUGE_PRESENT;
	if (prot & _PAGE_USER)
		pmd_prot |= PMD_HUGE_USER;
	if (prot & _PAGE_FILE)
		pmd_prot |= PMD_HUGE_FILE;
	if (prot & _PAGE_EXEC)
		pmd_prot |= PMD_HUGE_EXEC;
	/*
	 * _PAGE_COHERENT should always be set
	 */
	VM_BUG_ON(!(prot & _PAGE_COHERENT));

	if (prot & _PAGE_SAO)
		pmd_prot |= PMD_HUGE_SAO;
	if (prot & _PAGE_DIRTY)
		pmd_prot |= PMD_HUGE_DIRTY;
	if (prot & _PAGE_ACCESSED)
		pmd_prot |= PMD_HUGE_ACCESSED;
	if (prot & _PAGE_RW)
		pmd_prot |= PMD_HUGE_RW;

	pmd_val(pmd) |= pmd_prot;
	return pmd;
}

pmd_t pfn_pmd(unsigned long pfn, pgprot_t pgprot)
{
	pmd_t pmd;
	/*
	 * We cannot support that many PFNs
	 */
	VM_BUG_ON(pfn & PMD_HUGE_NOT_HUGETLB);
	pmd_val(pmd) = pfn << PMD_HUGE_RPN_SHIFT;
	pmd_val(pmd) |= PMD_ISHUGE;
	pmd = pmd_set_protbits(pmd, pgprot);
	return pmd;
}

pmd_t mk_pmd(struct page *page, pgprot_t pgprot)
{
	return pfn_pmd(page_to_pfn(page), pgprot);
}

pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{
	/* FIXME!! why are this bits cleared ? */
	pmd_val(pmd) &= ~(PMD_HUGE_PRESENT |
			  PMD_HUGE_RW |
			  PMD_HUGE_EXEC);
	pmd = pmd_set_protbits(pmd, newprot);
	return pmd;
}

/*
 * This is called at the end of handling a user page fault, when the
 * fault has been handled by updating a HUGE PMD entry in the linux page tables.
 * We use it to preload an HPTE into the hash table corresponding to
 * the updated linux HUGE PMD entry.
 */
void update_mmu_cache_pmd(struct vm_area_struct *vma, unsigned long addr,
			  pmd_t *pmd)
{
	/* FIXME!!
	 * Will be done in a later patch
	 */
}

#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/*
 * find_linux_pte returns the address of a linux pte for a given
 * effective address and directory.  If not found, it returns zero.
 */
pte_t *find_linux_pte(pgd_t *pgdir, unsigned long ea, unsigned int *hugepage)
{
	pgd_t *pg;
	pud_t *pu;
	pmd_t *pm;
	pte_t *pt = NULL;

	if (hugepage)
		*hugepage = 0;
	pg = pgdir + pgd_index(ea);
	if (!pgd_none(*pg)) {
		pu = pud_offset(pg, ea);
		if (!pud_none(*pu)) {
			pm = pmd_offset(pu, ea);
			if (pmd_large(*pm)) {
				/* THP page */
				if (hugepage) {
					*hugepage = 1;
					/*
					 * This should be ok, except for few
					 * flags. Most of the pte and hugepage
					 * pmd bits overlap. We don't use the
					 * returned value as pte_t in the caller.
					 */
					return (pte_t *)pm;
				} else
					return NULL;
			} else if (pmd_present(*pm))
				pt = pte_offset_kernel(pm, ea);
		}
	}
	return pt;
}
