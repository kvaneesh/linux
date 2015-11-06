#ifndef _ASM_POWERPC_TLBFLUSH_RADIX_H
#define _ASM_POWERPC_TLBFLUSH_RADIX_H

struct vm_area_struct;
struct mm_struct;
struct mmu_gather;

static inline int mmu_get_ap(int psize)
{
	return mmu_psize_defs[psize].ap;
}

extern void flush_rtlb_range(struct vm_area_struct *vma, unsigned long start,
			    unsigned long end);
extern void flush_rtlb_kernel_range(unsigned long start, unsigned long end);

extern void local_flush_rtlb_mm(struct mm_struct *mm);
extern void local_flush_rtlb_page(struct vm_area_struct *vma, unsigned long vmaddr);
extern void __local_flush_rtlb_page(struct mm_struct *mm, unsigned long vmaddr,
				    unsigned long ap, int nid);
extern void rtlb_flush(struct mmu_gather *tlb);
#ifdef CONFIG_SMP
extern void flush_rtlb_mm(struct mm_struct *mm);
extern void flush_rtlb_page(struct vm_area_struct *vma, unsigned long vmaddr);
extern void __flush_rtlb_page(struct mm_struct *mm, unsigned long vmaddr,
			      unsigned long ap, int nid);
#else
#define flush_rtlb_mm(mm)		local_flush_rtlb_mm(mm)
#define flush_rtlb_page(vma,addr)	local_flush_rtlb_page(vma,addr)
#define __flush_rtlb_page(mm,addr,p,i)	__local_flush_rtlb_page(mm,addr,p,i)
#endif

#endif
