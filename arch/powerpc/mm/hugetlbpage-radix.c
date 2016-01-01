#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/machdep.h>
#include <asm/mman.h>
#include <asm/tlb.h>

void flush_hugetlb_rpage(struct vm_area_struct *vma, unsigned long vmaddr)
{
	unsigned long ap;
	int local = mm_is_core_local(vma->vm_mm);
	struct hstate *hstate = hstate_file(vma->vm_file);

	ap = hstate_get_ap(hstate);
	__flush_rtlb_page(vma->vm_mm, vmaddr, ap, local);
}

void __local_flush_hugetlb_rpage(struct vm_area_struct *vma, unsigned long vmaddr)
{
	unsigned long ap;
	int local = mm_is_core_local(vma->vm_mm);
	struct hstate *hstate = hstate_file(vma->vm_file);

	ap = hstate_get_ap(hstate);
	__local_flush_rtlb_page(vma->vm_mm, vmaddr, ap, local);
}

/*
 * For radix we don't support hugepd.
 * sizes 1G and 2M
 */
pte_t *huge_rpte_alloc(struct mm_struct *mm, unsigned long addr,
		       unsigned long sz)
{
	pgd_t *pgd;
	pud_t *pud;
	pte_t *pte = NULL;

	pgd = pgd_offset(mm, addr);
	pud = pud_alloc(mm, pgd, addr);
	if (pud) {
		if (sz == PUD_SIZE)
			pte = (pte_t *)pud;
		else {
			BUG_ON(sz != PMD_SIZE);
			pte = (pte_t *)pmd_alloc(mm, pud, addr);
		}
	}
	BUG_ON(pte && !rpte_none(*pte) && !rpte_leaf(*pte));
	return pte;
}

/*
 * A vairant of hugetlb_get_unmapped_area doing topdown search
 * FIXME!! should we do as x86 does or non hugetlb area does ?
 * ie, use topdown or not based on mmap_is_legacy check ?
 */
unsigned long
hugetlb_get_radix_unmapped_area(struct file *file, unsigned long addr,
				unsigned long len, unsigned long pgoff,
				unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct hstate *h = hstate_file(file);
	struct vm_unmapped_area_info info;

	if (len & ~huge_page_mask(h))
		return -EINVAL;
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED) {
		if (prepare_hugepage_range(file, addr, len))
			return -EINVAL;
		return addr;
	}

	if (addr) {
		addr = ALIGN(addr, huge_page_size(h));
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
	/*
	 * We are always doing an topdown search here. Slice code
	 * does that too.
	 */
	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = PAGE_SIZE;
	info.high_limit = current->mm->mmap_base;
	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
	info.align_offset = 0;
	return vm_unmapped_area(&info);
}
