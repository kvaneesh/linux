/*
 *  TLB flush routines for radix kernels.
 *
 *  Copyright (C) 2015 Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/memblock.h>

#include <asm/tlb.h>
#include <asm/tlbflush.h>

static DEFINE_RAW_SPINLOCK(native_tlbie_lock);

static inline void __tlbiel_pid(unsigned long pid, int set)
{
	unsigned long rb,rs,ric,prs,r;

	rb = PPC_BIT(53); /* IS = 1 */
	rb |= set << PPC_BITLSHIFT(51);
	rs = ((unsigned long)pid) << PPC_BITLSHIFT(31);
	prs = 1; /* process scoped */
	r = 1;   /* raidx format */
	ric = 2;  /* invalidate all the caches */

	asm volatile("ptesync": : :"memory");
	asm volatile(".long 0x7c000224 | (%0 << 11) | (%1 << 16) |"
		     "(%2 << 17) | (%3 << 18) | (%4 << 21)"
		     : : "r"(rb), "i"(r), "i"(prs), "i"(ric), "r"(rs) : "memory");
	asm volatile("ptesync": : :"memory");
}

/*
 * We use 128 set in radix mode and 256 set in hpt mode.
 * FIXME!! this need to be derived from device tree. For now
 * do #define
 */
#define TLB_SET 128
static inline void _tlbiel_pid(unsigned long pid)
{
	int set;

	for (set = 0; set < TLB_SET; set++) {
		__tlbiel_pid(pid, set);
	}
	return;
}

static inline void _tlbie_pid(unsigned long pid)
{
	unsigned long rb,rs,ric,prs,r;

	rb = PPC_BIT(53); /* IS = 1 */
	rs = pid << PPC_BITLSHIFT(31);
	prs = 1; /* process scoped */
	r = 1;   /* raidx format */
	ric = 2;  /* invalidate all the caches */

	asm volatile("ptesync": : :"memory");
	asm volatile(".long 0x7c000264 | (%0 << 11) | (%1 << 16) |"
		     "(%2 << 17) | (%3 << 18) | (%4 << 21)"
		     : : "r"(rb), "i"(r), "i"(prs), "i"(ric), "r"(rs) : "memory");
	asm volatile("eieio; tlbsync; ptesync": : :"memory");
}

static inline void _tlbiel_va(unsigned long va, unsigned long pid,
			      unsigned long ap)
{
	unsigned long rb,rs,ric,prs,r;

	rb = va & ~(PPC_BITMASK(52, 63));
	rb |= ap << PPC_BITLSHIFT(58);
	rs = pid << PPC_BITLSHIFT(31);
	prs = 1; /* process scoped */
	r = 1;   /* raidx format */
	ric = 0;  /* no cluster flush yet */

	asm volatile("ptesync": : :"memory");
	asm volatile(".long 0x7c000224 | (%0 << 11) | (%1 << 16) |"
		     "(%2 << 17) | (%3 << 18) | (%4 << 21)"
		     : : "r"(rb), "i"(r), "i"(prs), "i"(ric), "r"(rs) : "memory");
	asm volatile("ptesync": : :"memory");
}

static inline void _tlbie_va(unsigned long va, unsigned long pid,
			     unsigned long ap)
{
	unsigned long rb,rs,ric,prs,r;

	rb = va & ~(PPC_BITMASK(52, 63));
	rb |= ap << PPC_BITLSHIFT(58);
	rs = pid << PPC_BITLSHIFT(31);
	prs = 1; /* process scoped */
	r = 1;   /* raidx format */
	ric = 0;  /* no cluster flush yet */

	asm volatile("ptesync": : :"memory");
	asm volatile(".long 0x7c000264 | (%0 << 11) | (%1 << 16) |"
		     "(%2 << 17) | (%3 << 18) | (%4 << 21)"
		     : : "r"(rb), "i"(r), "i"(prs), "i"(ric), "r"(rs) : "memory");
	asm volatile("eieio; tlbsync; ptesync": : :"memory");
}

/*
 * Base TLB flushing operations:
 *
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes kernel pages
 *
 *  - local_* variants of page and mm only apply to the current
 *    processor
 */
void local_flush_rtlb_mm(struct mm_struct *mm)
{
	unsigned int pid;

	preempt_disable();
	pid = mm->context.id;
	if (pid != MMU_NO_CONTEXT)
		_tlbiel_pid(pid);
	preempt_enable();
}
EXPORT_SYMBOL(local_flush_rtlb_mm);

void __local_flush_rtlb_page(struct mm_struct *mm, unsigned long vmaddr,
			    unsigned long ap, int nid)
{
	unsigned int pid;

	preempt_disable();
	pid = mm ? mm->context.id : 0;
	if (pid != MMU_NO_CONTEXT)
		_tlbiel_va(vmaddr, pid, ap);
	preempt_enable();
}

void local_flush_rtlb_page(struct vm_area_struct *vma, unsigned long vmaddr)
{
	__local_flush_rtlb_page(vma ? vma->vm_mm : NULL, vmaddr,
			       mmu_get_ap(mmu_virtual_psize), 0);
}
EXPORT_SYMBOL(local_flush_rtlb_page);

#ifdef CONFIG_SMP
static int mm_is_core_local(struct mm_struct *mm)
{
	return cpumask_subset(mm_cpumask(mm),
			      topology_sibling_cpumask(smp_processor_id()));
}

void flush_rtlb_mm(struct mm_struct *mm)
{
	unsigned int pid;

	preempt_disable();
	pid = mm->context.id;
	if (unlikely(pid == MMU_NO_CONTEXT))
		goto no_context;

	if (!mm_is_core_local(mm)) {
		int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);

		if (lock_tlbie)
			raw_spin_lock(&native_tlbie_lock);
		_tlbie_pid(pid);
		if (lock_tlbie)
			raw_spin_unlock(&native_tlbie_lock);
	} else
		_tlbiel_pid(pid);
no_context:
	preempt_enable();
}
EXPORT_SYMBOL(flush_rtlb_mm);

void __flush_rtlb_page(struct mm_struct *mm, unsigned long vmaddr,
		       unsigned long ap, int nid)
{
	unsigned int pid;

	preempt_disable();
	pid = mm ? mm->context.id : 0;
	if (unlikely(pid == MMU_NO_CONTEXT))
		goto bail;
	if (!mm_is_core_local(mm)) {
		int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);

		if (lock_tlbie)
			raw_spin_lock(&native_tlbie_lock);
		_tlbie_va(vmaddr, pid, ap);
		if (lock_tlbie)
			raw_spin_unlock(&native_tlbie_lock);
	} else
		_tlbiel_va(vmaddr, pid, ap);
bail:
	preempt_enable();
}

void flush_rtlb_page(struct vm_area_struct *vma, unsigned long vmaddr)
{
	__flush_rtlb_page(vma ? vma->vm_mm : NULL, vmaddr,
			 mmu_get_ap(mmu_virtual_psize), 0);
}
EXPORT_SYMBOL(flush_rtlb_page);

#endif /* CONFIG_SMP */

void flush_rtlb_kernel_range(unsigned long start, unsigned long end)
{
	int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);

	if (lock_tlbie)
		raw_spin_lock(&native_tlbie_lock);
	_tlbie_pid(0);
	if (lock_tlbie)
		raw_spin_unlock(&native_tlbie_lock);
}
EXPORT_SYMBOL(flush_rtlb_kernel_range);

/*
 * Currently, for range flushing, we just do a full mm flush. Because
 * we use this in code path where we don' track the page size.
 */
void flush_rtlb_range(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end)

{
	struct mm_struct *mm = vma->vm_mm;
	flush_rtlb_mm(mm);
}
EXPORT_SYMBOL(flush_rtlb_range);


void rtlb_flush(struct mmu_gather *tlb)
{
	struct mm_struct *mm = tlb->mm;
	flush_rtlb_mm(mm);
}
