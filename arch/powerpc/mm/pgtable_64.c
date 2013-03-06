/*
 *  This file contains ioremap and related functions for 64-bit machines.
 *
 *  Derived from arch/ppc64/mm/init.c
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 *  Modifications by Paul Mackerras (PowerMac) (paulus@samba.org)
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
 *
 */

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/stddef.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/prom.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgtable.h>
#include <asm/mmu.h>
#include <asm/smp.h>
#include <asm/machdep.h>
#include <asm/tlb.h>
#include <asm/processor.h>
#include <asm/cputable.h>
#include <asm/sections.h>
#include <asm/firmware.h>

#include "mmu_decl.h"

/* Some sanity checking */
#if TASK_SIZE_USER64 > PGTABLE_RANGE
#error TASK_SIZE_USER64 exceeds pagetable range
#endif

#ifdef CONFIG_PPC_STD_MMU_64
#if TASK_SIZE_USER64 > (1UL << (ESID_BITS + SID_SHIFT))
#error TASK_SIZE_USER64 exceeds user VSID range
#endif
#endif

unsigned long ioremap_bot = IOREMAP_BASE;

#ifdef CONFIG_PPC_MMU_NOHASH
static void *early_alloc_pgtable(unsigned long size)
{
	void *pt;

	if (init_bootmem_done)
		pt = __alloc_bootmem(size, size, __pa(MAX_DMA_ADDRESS));
	else
		pt = __va(memblock_alloc_base(size, size,
					 __pa(MAX_DMA_ADDRESS)));
	memset(pt, 0, size);

	return pt;
}
#endif /* CONFIG_PPC_MMU_NOHASH */

/*
 * map_kernel_page currently only called by __ioremap
 * map_kernel_page adds an entry to the ioremap page table
 * and adds an entry to the HPT, possibly bolting it
 */
int map_kernel_page(unsigned long ea, unsigned long pa, int flags)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	if (slab_is_available()) {
		pgdp = pgd_offset_k(ea);
		pudp = pud_alloc(&init_mm, pgdp, ea);
		if (!pudp)
			return -ENOMEM;
		pmdp = pmd_alloc(&init_mm, pudp, ea);
		if (!pmdp)
			return -ENOMEM;
		ptep = pte_alloc_kernel(pmdp, ea);
		if (!ptep)
			return -ENOMEM;
		set_pte_at(&init_mm, ea, ptep, pfn_pte(pa >> PAGE_SHIFT,
							  __pgprot(flags)));
	} else {
#ifdef CONFIG_PPC_MMU_NOHASH
		/* Warning ! This will blow up if bootmem is not initialized
		 * which our ppc64 code is keen to do that, we'll need to
		 * fix it and/or be more careful
		 */
		pgdp = pgd_offset_k(ea);
#ifdef PUD_TABLE_SIZE
		if (pgd_none(*pgdp)) {
			pudp = early_alloc_pgtable(PUD_TABLE_SIZE);
			BUG_ON(pudp == NULL);
			pgd_populate(&init_mm, pgdp, pudp);
		}
#endif /* PUD_TABLE_SIZE */
		pudp = pud_offset(pgdp, ea);
		if (pud_none(*pudp)) {
			pmdp = early_alloc_pgtable(PMD_TABLE_SIZE);
			BUG_ON(pmdp == NULL);
			pud_populate(&init_mm, pudp, pmdp);
		}
		pmdp = pmd_offset(pudp, ea);
		if (!pmd_present(*pmdp)) {
			ptep = early_alloc_pgtable(PAGE_SIZE);
			BUG_ON(ptep == NULL);
			pmd_populate_kernel(&init_mm, pmdp, ptep);
		}
		ptep = pte_offset_kernel(pmdp, ea);
		set_pte_at(&init_mm, ea, ptep, pfn_pte(pa >> PAGE_SHIFT,
							  __pgprot(flags)));
#else /* CONFIG_PPC_MMU_NOHASH */
		/*
		 * If the mm subsystem is not fully up, we cannot create a
		 * linux page table entry for this mapping.  Simply bolt an
		 * entry in the hardware page table.
		 *
		 */
		if (htab_bolt_mapping(ea, ea + PAGE_SIZE, pa, flags,
				      mmu_io_psize, mmu_kernel_ssize)) {
			printk(KERN_ERR "Failed to do bolted mapping IO "
			       "memory at %016lx !\n", pa);
			return -ENOMEM;
		}
#endif /* !CONFIG_PPC_MMU_NOHASH */
	}
	return 0;
}


/**
 * __ioremap_at - Low level function to establish the page tables
 *                for an IO mapping
 */
void __iomem * __ioremap_at(phys_addr_t pa, void *ea, unsigned long size,
			    unsigned long flags)
{
	unsigned long i;

	/* Make sure we have the base flags */
	if ((flags & _PAGE_PRESENT) == 0)
		flags |= pgprot_val(PAGE_KERNEL);

	/* Non-cacheable page cannot be coherent */
	if (flags & _PAGE_NO_CACHE)
		flags &= ~_PAGE_COHERENT;

	/* We don't support the 4K PFN hack with ioremap */
	if (flags & _PAGE_4K_PFN)
		return NULL;

	WARN_ON(pa & ~PAGE_MASK);
	WARN_ON(((unsigned long)ea) & ~PAGE_MASK);
	WARN_ON(size & ~PAGE_MASK);

	for (i = 0; i < size; i += PAGE_SIZE)
		if (map_kernel_page((unsigned long)ea+i, pa+i, flags))
			return NULL;

	return (void __iomem *)ea;
}

/**
 * __iounmap_from - Low level function to tear down the page tables
 *                  for an IO mapping. This is used for mappings that
 *                  are manipulated manually, like partial unmapping of
 *                  PCI IOs or ISA space.
 */
void __iounmap_at(void *ea, unsigned long size)
{
	WARN_ON(((unsigned long)ea) & ~PAGE_MASK);
	WARN_ON(size & ~PAGE_MASK);

	unmap_kernel_range((unsigned long)ea, size);
}

void __iomem * __ioremap_caller(phys_addr_t addr, unsigned long size,
				unsigned long flags, void *caller)
{
	phys_addr_t paligned;
	void __iomem *ret;

	/*
	 * Choose an address to map it to.
	 * Once the imalloc system is running, we use it.
	 * Before that, we map using addresses going
	 * up from ioremap_bot.  imalloc will use
	 * the addresses from ioremap_bot through
	 * IMALLOC_END
	 * 
	 */
	paligned = addr & PAGE_MASK;
	size = PAGE_ALIGN(addr + size) - paligned;

	if ((size == 0) || (paligned == 0))
		return NULL;

	if (mem_init_done) {
		struct vm_struct *area;

		area = __get_vm_area_caller(size, VM_IOREMAP,
					    ioremap_bot, IOREMAP_END,
					    caller);
		if (area == NULL)
			return NULL;

		area->phys_addr = paligned;
		ret = __ioremap_at(paligned, area->addr, size, flags);
		if (!ret)
			vunmap(area->addr);
	} else {
		ret = __ioremap_at(paligned, (void *)ioremap_bot, size, flags);
		if (ret)
			ioremap_bot += size;
	}

	if (ret)
		ret += addr & ~PAGE_MASK;
	return ret;
}

void __iomem * __ioremap(phys_addr_t addr, unsigned long size,
			 unsigned long flags)
{
	return __ioremap_caller(addr, size, flags, __builtin_return_address(0));
}

void __iomem * ioremap(phys_addr_t addr, unsigned long size)
{
	unsigned long flags = _PAGE_NO_CACHE | _PAGE_GUARDED;
	void *caller = __builtin_return_address(0);

	if (ppc_md.ioremap)
		return ppc_md.ioremap(addr, size, flags, caller);
	return __ioremap_caller(addr, size, flags, caller);
}

void __iomem * ioremap_wc(phys_addr_t addr, unsigned long size)
{
	unsigned long flags = _PAGE_NO_CACHE;
	void *caller = __builtin_return_address(0);

	if (ppc_md.ioremap)
		return ppc_md.ioremap(addr, size, flags, caller);
	return __ioremap_caller(addr, size, flags, caller);
}

void __iomem * ioremap_prot(phys_addr_t addr, unsigned long size,
			     unsigned long flags)
{
	void *caller = __builtin_return_address(0);

	/* writeable implies dirty for kernel addresses */
	if (flags & _PAGE_RW)
		flags |= _PAGE_DIRTY;

	/* we don't want to let _PAGE_USER and _PAGE_EXEC leak out */
	flags &= ~(_PAGE_USER | _PAGE_EXEC);

#ifdef _PAGE_BAP_SR
	/* _PAGE_USER contains _PAGE_BAP_SR on BookE using the new PTE format
	 * which means that we just cleared supervisor access... oops ;-) This
	 * restores it
	 */
	flags |= _PAGE_BAP_SR;
#endif

	if (ppc_md.ioremap)
		return ppc_md.ioremap(addr, size, flags, caller);
	return __ioremap_caller(addr, size, flags, caller);
}


/*  
 * Unmap an IO region and remove it from imalloc'd list.
 * Access to IO memory should be serialized by driver.
 */
void __iounmap(volatile void __iomem *token)
{
	void *addr;

	if (!mem_init_done)
		return;
	
	addr = (void *) ((unsigned long __force)
			 PCI_FIX_ADDR(token) & PAGE_MASK);
	if ((unsigned long)addr < ioremap_bot) {
		printk(KERN_WARNING "Attempt to iounmap early bolted mapping"
		       " at 0x%p\n", addr);
		return;
	}
	vunmap(addr);
}

void iounmap(volatile void __iomem *token)
{
	if (ppc_md.iounmap)
		ppc_md.iounmap(token);
	else
		__iounmap(token);
}

EXPORT_SYMBOL(ioremap);
EXPORT_SYMBOL(ioremap_wc);
EXPORT_SYMBOL(ioremap_prot);
EXPORT_SYMBOL(__ioremap);
EXPORT_SYMBOL(__ioremap_at);
EXPORT_SYMBOL(iounmap);
EXPORT_SYMBOL(__iounmap);
EXPORT_SYMBOL(__iounmap_at);

/*
 * For hugepage we have pfn in the pmd, we use PMD_HUGE_RPN_SHIFT bits for flags
 * For PTE page, we have a PTE_FRAG_SIZE (4K) aligned virtual address.
 */
struct page *pmd_page(pmd_t pmd)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (pmd_trans_huge(pmd))
		return pfn_to_page(pmd_pfn(pmd));
#endif
	return virt_to_page(pmd_page_vaddr(pmd));
}

#ifdef CONFIG_PPC_64K_PAGES
static pte_t *get_from_cache(struct mm_struct *mm)
{
	void *pte_frag, *ret;

	spin_lock(&mm->page_table_lock);
	ret = mm->context.pte_frag;
	if (ret) {
		pte_frag = ret + PTE_FRAG_SIZE;
		/*
		 * If we have taken up all the fragments mark PTE page NULL
		 */
		if (((unsigned long)pte_frag & ~PAGE_MASK) == 0)
			pte_frag = NULL;
		mm->context.pte_frag = pte_frag;
	}
	spin_unlock(&mm->page_table_lock);
	return (pte_t *)ret;
}

static pte_t *__alloc_for_cache(struct mm_struct *mm, int kernel)
{
	void *ret = NULL;
	struct page *page = alloc_page(GFP_KERNEL | __GFP_NOTRACK |
				       __GFP_REPEAT | __GFP_ZERO);
	if (!page)
		return NULL;

	ret = page_address(page);
	spin_lock(&mm->page_table_lock);
	/*
	 * If we find pgtable_page set, we return
	 * the allocated page with single fragement
	 * count.
	 */
	if (likely(!mm->context.pte_frag)) {
		atomic_set(&page->_count, PTE_FRAG_NR);
		mm->context.pte_frag = ret + PTE_FRAG_SIZE;
	}
	spin_unlock(&mm->page_table_lock);

	if (!kernel)
		pgtable_page_ctor(page);

	return (pte_t *)ret;
}

pte_t *page_table_alloc(struct mm_struct *mm, unsigned long vmaddr, int kernel)
{
	pte_t *pte;

	pte = get_from_cache(mm);
	if (pte)
		return pte;

	return __alloc_for_cache(mm, kernel);
}

void page_table_free(struct mm_struct *mm, unsigned long *table, int kernel)
{
	struct page *page = virt_to_page(table);
	if (put_page_testzero(page)) {
		if (!kernel)
			pgtable_page_dtor(page);
		free_hot_cold_page(page, 0);
	}
}

#ifdef CONFIG_SMP
static void page_table_free_rcu(void *table)
{
	struct page *page = virt_to_page(table);
	if (put_page_testzero(page)) {
		pgtable_page_dtor(page);
		free_hot_cold_page(page, 0);
	}
}

void pgtable_free_tlb(struct mmu_gather *tlb, void *table, int shift)
{
	unsigned long pgf = (unsigned long)table;

	BUG_ON(shift > MAX_PGTABLE_INDEX_SIZE);
	pgf |= shift;
	tlb_remove_table(tlb, (void *)pgf);
}

void __tlb_remove_table(void *_table)
{
	void *table = (void *)((unsigned long)_table & ~MAX_PGTABLE_INDEX_SIZE);
	unsigned shift = (unsigned long)_table & MAX_PGTABLE_INDEX_SIZE;

	if (!shift)
		/* PTE page needs special handling */
		page_table_free_rcu(table);
	else {
		BUG_ON(shift > MAX_PGTABLE_INDEX_SIZE);
		kmem_cache_free(PGT_CACHE(shift), table);
	}
}
#else
void pgtable_free_tlb(struct mmu_gather *tlb, void *table, int shift)
{
	if (!shift) {
		/* PTE page needs special handling */
		struct page *page = virt_to_page(table);
		if (put_page_testzero(page)) {
			pgtable_page_dtor(page);
			free_hot_cold_page(page, 0);
		}
	} else {
		BUG_ON(shift > MAX_PGTABLE_INDEX_SIZE);
		kmem_cache_free(PGT_CACHE(shift), table);
	}
}
#endif
#endif /* CONFIG_PPC_64K_PAGES */

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
	: "r" (pmdp), "i" (_PAGE_SPLITTING), "m" (*pmdp), "i" (_PAGE_BUSY)
	: "cc" );
#else
	old = pmd_val(*pmdp);
	*pmdp = __pmd(old | _PAGE_SPLITTING);
#endif
	/*
	 * If we didn't had the splitting flag set, go and flush the
	 * HPTE entries and serialize against gup fast.
	 */
	if (!(old & _PAGE_SPLITTING)) {
#ifdef CONFIG_PPC_STD_MMU_64
		/* We need to flush the hpte */
		if (old & _PAGE_HASHPTE)
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
	pmd = __pmd(pmd_val(pmd) & ~_PAGE_THP_HPTEFLAGS);
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
	pmd_hugepage_update(vma->vm_mm, address, pmdp, _PAGE_PRESENT);
	flush_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
}

/*
 * A linux hugepage PMD was changed and the corresponding hash table entries
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

	for (i = 0; i < (HUGE_PAGE_SIZE >> shift); i++) {
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
	pmd_val(pmd) |= pgprot_val(pgprot);
	return pmd;
}

pmd_t pfn_pmd(unsigned long pfn, pgprot_t pgprot)
{
	pmd_t pmd;
	/*
	 * For a valid pte, we would have _PAGE_PRESENT or _PAGE_FILE always
	 * set. We use this to check THP page at pmd level.
	 * leaf pte for huge page, bottom two bits != 00
	 */
	pmd_val(pmd) = pfn << PTE_RPN_SHIFT;
	pmd_val(pmd) |= _PAGE_THP_HUGE;
	pmd = pmd_set_protbits(pmd, pgprot);
	return pmd;
}

pmd_t mk_pmd(struct page *page, pgprot_t pgprot)
{
	return pfn_pmd(page_to_pfn(page), pgprot);
}

pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{

	pmd_val(pmd) &= _HPAGE_CHG_MASK;
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
	return;
}

int has_transparent_hugepage(void)
{
	if (!mmu_has_feature(MMU_FTR_16M_PAGE))
		return 0;
	/*
	 * We support THP only if HPAGE_SHIFT is 16MB.
	 */
	if (!HPAGE_SHIFT || (HPAGE_SHIFT != mmu_psize_defs[MMU_PAGE_16M].shift))
		return 0;
	/*
	 * We need to make sure that we support 16MB hugepage in a segement
	 * with base page size 64K or 4K. We only enable THP with a PAGE_SIZE
	 * of 64K.
	 */
	/*
	 * If we have 64K HPTE, we will be using that by default
	 */
	if (mmu_psize_defs[MMU_PAGE_64K].shift &&
	    (mmu_psize_defs[MMU_PAGE_64K].penc[MMU_PAGE_16M] == -1))
		return 0;
	/*
	 * Ok we only have 4K HPTE
	 */
	if (mmu_psize_defs[MMU_PAGE_4K].penc[MMU_PAGE_16M] == -1)
		return 0;

	return 1;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

pmd_t pmdp_get_and_clear(struct mm_struct *mm,
			 unsigned long addr, pmd_t *pmdp)
{
	pmd_t old_pmd;
	unsigned long old;
	/*
	 * khugepaged calls this for normal pmd also
	 */
	if (pmd_trans_huge(*pmdp)) {
		old = pmd_hugepage_update(mm, addr, pmdp, ~0UL);
		old_pmd = __pmd(old);
	} else {
		old_pmd = *pmdp;
		pmd_clear(pmdp);
	}
	return old_pmd;
}
