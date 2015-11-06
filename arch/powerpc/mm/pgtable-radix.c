/*
 * page table handling routines for radix page table
 *
 *  Copyright (C) 2015 Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 */
#include <linux/sched.h>
#include <linux/memblock.h>

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/dma.h>
#include <asm/machdep.h>
#include <asm/mmu.h>
#include <asm/firmware.h>

struct prtb_entry *process_tb;
struct patb_entry *partition_tb;

static int native_update_partition_table(u64 patb1)
{
	partition_tb->patb1 = cpu_to_be64(patb1);
	return 0;
}

static __ref void *early_alloc_pgtable(unsigned long size)
{
	void *pt;

	pt = __va(memblock_alloc_base(size, size, __pa(MAX_DMA_ADDRESS)));
	memset(pt, 0, size);

	return pt;
}

/*
 * set_pte stores a linux PTE into the linux page table.
 */
void set_rpte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
		 pte_t pte)
{
	/*
	 * When handling numa faults, we already have the pte marked
	 * _PAGE_PRESENT, but we can be sure that it is not in hpte.
	 * Hence we can use set_pte_at for them.
	 */
	VM_WARN_ON(rpte_present(*ptep));

#if 0 /* Do we need to filter ? */
	/* Note: mm->context.id might not yet have been assigned as
	 * this context might not have been activated yet when this
	 * is called.
	 */
	pte = set_pte_filter(pte);
#endif
	/* Perform the setting of the PTE */
	__set_rpte_at(mm, addr, ptep, pte, 0);
}

int map_radix_kernel_page(unsigned long ea, unsigned long pa,
			  pgprot_t flags,
			  unsigned int map_page_size)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;
	/*
	 * Make sure task size is correct as per the max adddr
	 */
	BUILD_BUG_ON(TASK_SIZE_USER64 > RPGTABLE_RANGE);
	if (slab_is_available()) {
		pgdp = pgd_offset_k(ea);
		pudp = pud_alloc(&init_mm, pgdp, ea);
		if (!pudp)
			return -ENOMEM;
		if (map_page_size == PUD_SIZE) {
			ptep = (pte_t *)pudp;
			goto set_the_pte;
		}
		pmdp = pmd_alloc(&init_mm, pudp, ea);
		if (!pmdp)
			return -ENOMEM;
		if (map_page_size == PMD_SIZE) {
			ptep = (pte_t *)pudp;
			goto set_the_pte;
		}
		ptep = pte_alloc_kernel(pmdp, ea);
		if (!ptep)
			return -ENOMEM;
	} else {
		pgdp = pgd_offset_k(ea);
		if (pgd_none(*pgdp)) {
			pudp = early_alloc_pgtable(RPUD_TABLE_SIZE);
			BUG_ON(pudp == NULL);
			rpgd_populate(&init_mm, pgdp, pudp);
		}
		pudp = pud_offset(pgdp, ea);
		if (map_page_size == PUD_SIZE) {
			ptep = (pte_t *)pudp;
			goto set_the_pte;
		}
		if (pud_none(*pudp)) {
			pmdp = early_alloc_pgtable(RPMD_TABLE_SIZE);
			BUG_ON(pmdp == NULL);
			rpud_populate(&init_mm, pudp, pmdp);
		}
		pmdp = pmd_offset(pudp, ea);
		if (map_page_size == PMD_SIZE) {
			ptep = (pte_t *)pudp;
			goto set_the_pte;
		}
		if (!pmd_present(*pmdp)) {
			ptep = early_alloc_pgtable(PAGE_SIZE);
			BUG_ON(ptep == NULL);
			rpmd_populate_kernel(&init_mm, pmdp, ptep);
		}
		ptep = pte_offset_kernel(pmdp, ea);
	}

set_the_pte:
	set_rpte_at(&init_mm, ea, ptep, pfn_pte(pa >> PAGE_SHIFT, flags));
	smp_wmb();
	return 0;
}

static void __init radix_init_pgtable(void)
{
	u64 base, end;
	unsigned long rts_field;
	struct memblock_region *reg;
	unsigned long linear_page_size;

	pr_info("Mapping linear mapping in radix tree...\n");

	if (mmu_psize_defs[MMU_PAGE_1G].shift)
		linear_page_size = PUD_SIZE;
	else if (mmu_psize_defs[MMU_PAGE_2M].shift)
		linear_page_size = PMD_SIZE;
	else
		linear_page_size = PAGE_SIZE;

	pr_info("Mapping kernel with page_size 0x%lx\n", linear_page_size);
	/* We don't support slb for radix */
	mmu_slb_size = 0;
	/* Create the linear mapping, using standard page size for now */
	for_each_memblock(memory, reg) {
		base = _ALIGN_UP(reg->base, linear_page_size);
		end = _ALIGN_DOWN(reg->base + reg->size, linear_page_size);

		while (base < end) {
			map_radix_kernel_page((unsigned long)__va(base),
					      base, RPAGE_KERNEL_X,
					      linear_page_size);
			base += linear_page_size;
		}
	}
	/*
	 * Allocate Partition table and process table for the
	 * host.
	 */
	BUILD_BUG_ON_MSG((PRTB_SIZE_SHIFT > 23), "Process table size too large.");
	process_tb = early_alloc_pgtable(1UL << PRTB_SIZE_SHIFT);
	/*
	 * Fill in the process table.
	 * we support 52 bits, hence 52-28 = 24, 11000
	 */
	rts_field = 3ull << PPC_BITLSHIFT(2);
	process_tb->prtb0 = cpu_to_be64(rts_field | __pa(init_mm.pgd) | RPGD_INDEX_SIZE);
	/*
	 * Fill in the partition table, 64k size for process table.
	 */
	ppc_md.update_partition_table(__pa(process_tb) | (PRTB_SIZE_SHIFT - 12) | PATB_GR);
	pr_info("Process table %p and radix root for kernel: %p\n", process_tb, init_mm.pgd);
}

static void __init radix_init_partition_table(void)
{
	unsigned long rts_field;
	/*
	 * we support 52 bits, hence 52-28 = 24, 11000
	 */
	rts_field = 3ull << PPC_BITLSHIFT(2);

	BUILD_BUG_ON_MSG((PATB_SIZE_SHIFT > 24), "Partition table size too large.");
	partition_tb = early_alloc_pgtable(1UL << PATB_SIZE_SHIFT);
	partition_tb->patb0 = cpu_to_be64(rts_field | __pa(init_mm.pgd) |
					  RPGD_INDEX_SIZE | PATB_HR);
	printk("Partition table %p\n", partition_tb);

	memblock_set_current_limit(MEMBLOCK_ALLOC_ANYWHERE);
	/*
	 * update partition table control register,
	 * 64 K size.
	 */
	mtspr(SPRN_PTCR, __pa(partition_tb) | (PATB_SIZE_SHIFT - 12));
}

void __init radix_init_native(void)
{
	ppc_md.update_partition_table = native_update_partition_table;
}

void __init rearly_init_mmu(void)
{
	/* FIXME: Use a different layout ? Use huge pages ? */
#ifdef CONFIG_PPC_64K_PAGES
	mmu_linear_psize = MMU_PAGE_64K;
	mmu_virtual_psize = MMU_PAGE_64K;
	mmu_vmalloc_psize = MMU_PAGE_64K;
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	mmu_vmemmap_psize = MMU_PAGE_64K;
#endif
	mmu_io_psize = MMU_PAGE_64K;
#else
	mmu_linear_psize = MMU_PAGE_4K;
	mmu_virtual_psize = MMU_PAGE_4K;
	mmu_vmalloc_psize = MMU_PAGE_4K;
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	mmu_vmemmap_psize = MMU_PAGE_4K;
#endif
	mmu_io_psize = MMU_PAGE_4K;
#endif
	/*
	 * initialize global variables
	 */
	__kernel_page_prot = RPAGE_KERNEL;
	__page_none = RPAGE_NONE;
	__ptrs_per_pte = PTRS_PER_RPTE;
	__ptrs_per_pmd = PTRS_PER_RPMD;
	__pmd_shift    = RPMD_SHIFT;
#ifndef __PAGETABLE_PUD_FOLDED
	__pud_shift    = RPUD_SHIFT;
#endif
	__pgdir_shift  = RPGDIR_SHIFT;
	__kernel_virt_start = RKERN_VIRT_START;
	__kernel_virt_size = RKERN_VIRT_SIZE;
	vmemmap = (struct page *)RVMEMMAP_BASE;
	__vmalloc_start = RVMALLOC_START;
	__vmalloc_end = RVMALLOC_END;
	__page_no_cache = _RPAGE_NO_CACHE;
	__page_guarded = _RPAGE_GUARDED;
	__page_user = _RPAGE_USER;
	__page_coherent = _RPAGE_COHERENT;
	__page_present = _RPAGE_PRESENT;
	__page_kernel_exec = RPAGE_KERNEL_EXEC;
	ioremap_bot = IOREMAP_BASE;

	mmu_psize_defs[MMU_PAGE_64K].shift = 16;
	mmu_psize_defs[MMU_PAGE_64K].sllp = 0x0110;

	if (!firmware_has_feature(FW_FEATURE_LPAR)) {
		/* 2M */
		mmu_psize_defs[MMU_PAGE_2M].shift = 21;
		/* FIXME!! Fix sllp based on device tree */
		mmu_psize_defs[MMU_PAGE_2M].sllp = 0x0010;

		/* 1G */
		mmu_psize_defs[MMU_PAGE_1G].shift = 30;
		/* FIXME!! Fix sllp based on device tree */
		mmu_psize_defs[MMU_PAGE_1G].sllp = 0x0020;
	}

	if (!firmware_has_feature(FW_FEATURE_LPAR))
		radix_init_partition_table();

	radix_init_pgtable();
}

void rearly_init_mmu_secondary(void)
{
	/* XXX TODO: Setup SDR etc... */
}

void rsetup_initial_memory_limit(phys_addr_t first_memblock_base,
				phys_addr_t first_memblock_size)
{
	/* Finally limit subsequent allocations */
	memblock_set_current_limit(first_memblock_base + first_memblock_size);
}

static void pgd_ctor(void *addr)
{
	memset(addr, 0, RPGD_TABLE_SIZE);
}

static void pmd_ctor(void *addr)
{
	memset(addr, 0, RPMD_TABLE_SIZE);
}

void rpgtable_cache_init(void)
{
	pgtable_cache_add(RPGD_INDEX_SIZE, pgd_ctor);
	pgtable_cache_add(RPMD_INDEX_SIZE, pmd_ctor);

	if (!PGT_CACHE(RPGD_INDEX_SIZE) || !PGT_CACHE(RPMD_INDEX_SIZE))
		panic("Couldn't allocate pgtable caches");
	/* PUD_INDEX == PMD_INDEX */
	if (RPUD_INDEX_SIZE && !PGT_CACHE(RPUD_INDEX_SIZE))
		panic("Couldn't allocate pud pgtable caches");
}

pgtable_t rpte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *page;

	page = alloc_page(PGALLOC_GFP);
	if (!page)
		return NULL;
	if (!pgtable_page_ctor(page)) {
		__free_page(page);
		return NULL;
	}
	return page_address(page);
}

static pgprot_t radix_protection_map[16] = {
	__RP000, __RP001, __RP010, __RP011, __RP100, __RP101, __RP110, __RP111,
	__RS000, __RS001, __RS010, __RS011, __RS100, __RS101, __RS110, __RS111
};

pgprot_t rvm_get_page_prot(unsigned long vm_flags)
{
	pgprot_t prot_soa = __pgprot(0);

	if (vm_flags & VM_SAO)
		prot_soa = __pgprot(_RPAGE_SAO);

	return __pgprot(pgprot_val(radix_protection_map[vm_flags &
				(VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)]) |
			pgprot_val(prot_soa));
}
EXPORT_SYMBOL(rvm_get_page_prot);

#ifdef CONFIG_SPARSEMEM_VMEMMAP
void __meminit rvmemmap_create_mapping(unsigned long start,
				      unsigned long page_size,
				      unsigned long phys)
{
	/* Create a PTE encoding */
	unsigned long flags = _RPAGE_PRESENT | _RPAGE_ACCESSED |
				_RPAGE_KERNEL_RW;

	/* FIXME!! Assume page_size == PAGE_SIZE for now */
	BUG_ON(map_radix_kernel_page(start, phys, __pgprot(flags), PAGE_SIZE));
}

#ifdef CONFIG_MEMORY_HOTPLUG
void rvmemmap_remove_mapping(unsigned long start, unsigned long page_size)
{
	/* FIXME!! intel does more. We should free page tables mapping vmemmap ? */
}
#endif
#endif
