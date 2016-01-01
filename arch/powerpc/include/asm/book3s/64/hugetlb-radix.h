#ifndef _ASM_POWERPC_BOOK3S_64_HUGETLB_RADIX_H
#define _ASM_POWERPC_BOOK3S_64_HUGETLB_RADIX_H
/*
 * For radix we want generic code to handle hugetlb. But then if we want
 * both hash and radix to be enabled together we need to workaround the
 * limitations.
 */
void flush_hugetlb_rpage(struct vm_area_struct *vma, unsigned long vmaddr);
void __local_flush_hugetlb_rpage(struct vm_area_struct *vma, unsigned long vmaddr);

static inline void hugetlb_free_rpgd_range(struct mmu_gather *tlb,
					   unsigned long addr, unsigned long end,
					   unsigned long floor,
					   unsigned long ceiling)
{
	free_pgd_range(tlb, addr, end, floor, ceiling);
}

extern unsigned long
hugetlb_get_radix_unmapped_area(struct file *file, unsigned long addr,
				unsigned long len, unsigned long pgoff,
				unsigned long flags);
extern pte_t *huge_rpte_alloc(struct mm_struct *mm, unsigned long addr,
			      unsigned long sz);

static inline int hstate_get_ap(struct hstate *hstate)
{
	unsigned long ap, shift;

	shift = huge_page_shift(hstate);
	if (shift == mmu_psize_defs[MMU_PAGE_2M].shift)
		ap = mmu_get_ap(MMU_PAGE_2M);
	else if (shift == mmu_psize_defs[MMU_PAGE_1G].shift)
		ap = mmu_get_ap(MMU_PAGE_1G);
	else {
		WARN(1, "Wrong huge page shift\n");
		return 0;
	}
	return ap;
}
#endif
