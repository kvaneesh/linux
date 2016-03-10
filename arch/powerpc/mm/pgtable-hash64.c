/*
 * Copyright IBM Corporation, 2015
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

/*
 * PPC64 THP Support for hash based MMUs
 */
#include <linux/sched.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>

#include "mmu_decl.h"

#ifdef CONFIG_SPARSEMEM_VMEMMAP
/*
 * On hash-based CPUs, the vmemmap is bolted in the hash table.
 *
 */
int __meminit hlvmemmap_create_mapping(unsigned long start,
				       unsigned long page_size,
				       unsigned long phys)
{
	int rc = htab_bolt_mapping(start, start + page_size, phys,
				   pgprot_val(PAGE_KERNEL),
				   mmu_vmemmap_psize, mmu_kernel_ssize);
	if (rc < 0) {
		int rc2 = htab_remove_mapping(start, start + page_size,
					      mmu_vmemmap_psize,
					      mmu_kernel_ssize);
		BUG_ON(rc2 && (rc2 != -ENOENT));
	}
	return rc;
}

#ifdef CONFIG_MEMORY_HOTPLUG
void hlvmemmap_remove_mapping(unsigned long start,
			      unsigned long page_size)
{
	int rc = htab_remove_mapping(start, start + page_size,
				     mmu_vmemmap_psize,
				     mmu_kernel_ssize);
	BUG_ON((rc < 0) && (rc != -ENOENT));
	WARN_ON(rc == -ENOENT);
}
#endif
#endif /* CONFIG_SPARSEMEM_VMEMMAP */

/*
 * map_kernel_page currently only called by __ioremap
 * map_kernel_page adds an entry to the ioremap page table
 * and adds an entry to the HPT, possibly bolting it
 */
int hlmap_kernel_page(unsigned long ea, unsigned long pa, unsigned long flags)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	BUILD_BUG_ON(TASK_SIZE_USER64 > H_PGTABLE_RANGE);
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
	}

	smp_wmb();
	return 0;
}
