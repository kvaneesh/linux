/*
 * PowerPC64 SLB support.
 *
 * Copyright (C) 2004 David Gibson <dwg@au.ibm.com>, IBM
 * Based on earlier code written by:
 * Dave Engebretsen and Mike Corrigan {engebret|mikejc}@us.ibm.com
 *    Copyright (c) 2001 Dave Engebretsen
 * Copyright (C) 2002 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/paca.h>
#include <asm/cputable.h>
#include <asm/cacheflush.h>
#include <asm/smp.h>
#include <linux/compiler.h>
#include <asm/udbg.h>
#include <asm/code-patching.h>

#include <linux/context_tracking.h>
#include <linux/slab.h>
#include <linux/memblock.h>

enum slb_index {
	LINEAR_INDEX	= 0, /* Kernel linear map  (0xc000000000000000) */
	VMALLOC_INDEX	= 1, /* Kernel virtual map (0xd000000000000000) */
	KSTACK_INDEX	= 2, /* Kernel stack map */
};

extern void slb_allocate_realmode(unsigned long ea);
extern void slb_allocate_user(unsigned long ea);

static void slb_allocate(unsigned long ea)
{
	/* Currently, we do real mode for all SLBs including user, but
	 * that will change if we bring back dynamic VSIDs
	 */
	slb_allocate_realmode(ea);
}

#define slb_esid_mask(ssize)	\
	(((ssize) == MMU_SEGSIZE_256M)? ESID_MASK: ESID_MASK_1T)

static inline unsigned long mk_esid_data(unsigned long ea, int ssize,
					 enum slb_index index)
{
	return (ea & slb_esid_mask(ssize)) | SLB_ESID_V | index;
}

static inline unsigned long mk_vsid_data(unsigned long ea, int ssize,
					 unsigned long flags)
{
	return (get_kernel_vsid(ea, ssize) << slb_vsid_shift(ssize)) | flags |
		((unsigned long) ssize << SLB_VSID_SSIZE_SHIFT);
}

static inline void slb_shadow_update(unsigned long ea, int ssize,
				     unsigned long flags,
				     enum slb_index index)
{
	struct slb_shadow *p = get_slb_shadow();

	/*
	 * Clear the ESID first so the entry is not valid while we are
	 * updating it.  No write barriers are needed here, provided
	 * we only update the current CPU's SLB shadow buffer.
	 */
	p->save_area[index].esid = 0;
	p->save_area[index].vsid = cpu_to_be64(mk_vsid_data(ea, ssize, flags));
	p->save_area[index].esid = cpu_to_be64(mk_esid_data(ea, ssize, index));
}

static inline void slb_shadow_clear(enum slb_index index)
{
	get_slb_shadow()->save_area[index].esid = 0;
}

static inline void create_shadowed_slbe(unsigned long ea, int ssize,
					unsigned long flags,
					enum slb_index index)
{
	/*
	 * Updating the shadow buffer before writing the SLB ensures
	 * we don't get a stale entry here if we get preempted by PHYP
	 * between these two statements.
	 */
	slb_shadow_update(ea, ssize, flags, index);

	asm volatile("slbmte  %0,%1" :
		     : "r" (mk_vsid_data(ea, ssize, flags)),
		       "r" (mk_esid_data(ea, ssize, index))
		     : "memory" );
}

static void __slb_flush_and_rebolt(void)
{
	/* If you change this make sure you change SLB_NUM_BOLTED
	 * and PR KVM appropriately too. */
	unsigned long linear_llp, vmalloc_llp, lflags, vflags;
	unsigned long ksp_esid_data, ksp_vsid_data;

	linear_llp = mmu_psize_defs[mmu_linear_psize].sllp;
	vmalloc_llp = mmu_psize_defs[mmu_vmalloc_psize].sllp;
	lflags = SLB_VSID_KERNEL | linear_llp;
	vflags = SLB_VSID_KERNEL | vmalloc_llp;

	ksp_esid_data = mk_esid_data(get_paca()->kstack, mmu_kernel_ssize, KSTACK_INDEX);
	if ((ksp_esid_data & ~0xfffffffUL) <= PAGE_OFFSET) {
		ksp_esid_data &= ~SLB_ESID_V;
		ksp_vsid_data = 0;
		slb_shadow_clear(KSTACK_INDEX);
	} else {
		/* Update stack entry; others don't change */
		slb_shadow_update(get_paca()->kstack, mmu_kernel_ssize, lflags, KSTACK_INDEX);
		ksp_vsid_data =
			be64_to_cpu(get_slb_shadow()->save_area[KSTACK_INDEX].vsid);
	}

	/* We need to do this all in asm, so we're sure we don't touch
	 * the stack between the slbia and rebolting it. */
	asm volatile("isync\n"
		     "slbia\n"
		     /* Slot 1 - first VMALLOC segment */
		     "slbmte	%0,%1\n"
		     /* Slot 2 - kernel stack */
		     "slbmte	%2,%3\n"
		     "isync"
		     :: "r"(mk_vsid_data(H_VMALLOC_START, mmu_kernel_ssize, vflags)),
		        "r"(mk_esid_data(H_VMALLOC_START, mmu_kernel_ssize, 1)),
		        "r"(ksp_vsid_data),
		        "r"(ksp_esid_data)
		     : "memory");
}

void slb_flush_and_rebolt(void)
{

	WARN_ON(!irqs_disabled());

	/*
	 * We can't take a PMU exception in the following code, so hard
	 * disable interrupts.
	 */
	hard_irq_disable();

	__slb_flush_and_rebolt();
	get_paca()->slb_cache_ptr = 0;
}

void slb_vmalloc_update(void)
{
	unsigned long vflags;

	vflags = SLB_VSID_KERNEL | mmu_psize_defs[mmu_vmalloc_psize].sllp;
	slb_shadow_update(H_VMALLOC_START, mmu_kernel_ssize, vflags, VMALLOC_INDEX);
	slb_flush_and_rebolt();
}

/* Helper function to compare esids.  There are four cases to handle.
 * 1. The system is not 1T segment size capable.  Use the GET_ESID compare.
 * 2. The system is 1T capable, both addresses are < 1T, use the GET_ESID compare.
 * 3. The system is 1T capable, only one of the two addresses is > 1T.  This is not a match.
 * 4. The system is 1T capable, both addresses are > 1T, use the GET_ESID_1T macro to compare.
 */
static inline int esids_match(unsigned long addr1, unsigned long addr2)
{
	int esid_1t_count;

	/* System is not 1T segment size capable. */
	if (!mmu_has_feature(MMU_FTR_1T_SEGMENT))
		return (GET_ESID(addr1) == GET_ESID(addr2));

	esid_1t_count = (((addr1 >> SID_SHIFT_1T) != 0) +
				((addr2 >> SID_SHIFT_1T) != 0));

	/* both addresses are < 1T */
	if (esid_1t_count == 0)
		return (GET_ESID(addr1) == GET_ESID(addr2));

	/* One address < 1T, the other > 1T.  Not a match */
	if (esid_1t_count == 1)
		return 0;

	/* Both addresses are > 1T. */
	return (GET_ESID_1T(addr1) == GET_ESID_1T(addr2));
}

/* Flush all user entries from the segment table of the current processor. */
void switch_slb(struct task_struct *tsk, struct mm_struct *mm)
{
	unsigned long offset;
	unsigned long slbie_data = 0;
	unsigned long pc = KSTK_EIP(tsk);
	unsigned long stack = KSTK_ESP(tsk);
	unsigned long exec_base;

	/*
	 * We need interrupts hard-disabled here, not just soft-disabled,
	 * so that a PMU interrupt can't occur, which might try to access
	 * user memory (to get a stack trace) and possible cause an SLB miss
	 * which would update the slb_cache/slb_cache_ptr fields in the PACA.
	 */
	hard_irq_disable();
	offset = get_paca()->slb_cache_ptr;
	if (!mmu_has_feature(MMU_FTR_NO_SLBIE_B) &&
	    offset <= SLB_CACHE_ENTRIES) {
		int i;
		asm volatile("isync" : : : "memory");
		for (i = 0; i < offset; i++) {
			slbie_data = (unsigned long)get_paca()->slb_cache[i]
				<< SID_SHIFT; /* EA */
			slbie_data |= user_segment_size(slbie_data)
				<< SLBIE_SSIZE_SHIFT;
			slbie_data |= SLBIE_C; /* C set for user addresses */
			asm volatile("slbie %0" : : "r" (slbie_data));
		}
		asm volatile("isync" : : : "memory");
	} else {
		__slb_flush_and_rebolt();
	}

	/* Workaround POWER5 < DD2.1 issue */
	if (offset == 1 || offset > SLB_CACHE_ENTRIES)
		asm volatile("slbie %0" : : "r" (slbie_data));

	get_paca()->slb_cache_ptr = 0;
	copy_mm_to_paca(&mm->context);

	/*
	 * preload some userspace segments into the SLB.
	 * Almost all 32 and 64bit PowerPC executables are linked at
	 * 0x10000000 so it makes sense to preload this segment.
	 */
	exec_base = 0x10000000;

	if (is_kernel_addr(pc) || is_kernel_addr(stack) ||
	    is_kernel_addr(exec_base))
		return;

	slb_allocate(pc);

	if (!esids_match(pc, stack))
		slb_allocate(stack);

	if (!esids_match(pc, exec_base) &&
	    !esids_match(stack, exec_base))
		slb_allocate(exec_base);
}

static inline void patch_slb_encoding(unsigned int *insn_addr,
				      unsigned int immed)
{

	/*
	 * This function patches either an li or a cmpldi instruction with
	 * a new immediate value. This relies on the fact that both li
	 * (which is actually addi) and cmpldi both take a 16-bit immediate
	 * value, and it is situated in the same location in the instruction,
	 * ie. bits 16-31 (Big endian bit order) or the lower 16 bits.
	 * The signedness of the immediate operand differs between the two
	 * instructions however this code is only ever patching a small value,
	 * much less than 1 << 15, so we can get away with it.
	 * To patch the value we read the existing instruction, clear the
	 * immediate value, and or in our new value, then write the instruction
	 * back.
	 */
	unsigned int insn = (*insn_addr & 0xffff0000) | immed;
	patch_instruction(insn_addr, insn);
}

extern u32 slb_miss_kernel_load_linear[];
extern u32 slb_miss_kernel_load_io[];
extern u32 slb_compare_rr_to_size[];
extern u32 slb_miss_kernel_load_vmemmap[];

void slb_set_size(u16 size)
{
	if (mmu_slb_size == size)
		return;

	mmu_slb_size = size;
	patch_slb_encoding(slb_compare_rr_to_size, mmu_slb_size);
}

void slb_initialize(void)
{
	unsigned long linear_llp, vmalloc_llp, io_llp;
	unsigned long lflags, vflags;
	static int slb_encoding_inited;
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	unsigned long vmemmap_llp;
#endif

	/* Prepare our SLB miss handler based on our page size */
	linear_llp = mmu_psize_defs[mmu_linear_psize].sllp;
	io_llp = mmu_psize_defs[mmu_io_psize].sllp;
	vmalloc_llp = mmu_psize_defs[mmu_vmalloc_psize].sllp;
	get_paca()->vmalloc_sllp = SLB_VSID_KERNEL | vmalloc_llp;
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	vmemmap_llp = mmu_psize_defs[mmu_vmemmap_psize].sllp;
#endif
	if (!slb_encoding_inited) {
		slb_encoding_inited = 1;
		patch_slb_encoding(slb_miss_kernel_load_linear,
				   SLB_VSID_KERNEL | linear_llp);
		patch_slb_encoding(slb_miss_kernel_load_io,
				   SLB_VSID_KERNEL | io_llp);
		patch_slb_encoding(slb_compare_rr_to_size,
				   mmu_slb_size);

		pr_devel("SLB: linear  LLP = %04lx\n", linear_llp);
		pr_devel("SLB: io      LLP = %04lx\n", io_llp);

#ifdef CONFIG_SPARSEMEM_VMEMMAP
		patch_slb_encoding(slb_miss_kernel_load_vmemmap,
				   SLB_VSID_KERNEL | vmemmap_llp);
		pr_devel("SLB: vmemmap LLP = %04lx\n", vmemmap_llp);
#endif
	}

	get_paca()->stab_rr = SLB_NUM_BOLTED;

	lflags = SLB_VSID_KERNEL | linear_llp;
	vflags = SLB_VSID_KERNEL | vmalloc_llp;

	/* Invalidate the entire SLB (even entry 0) & all the ERATS */
	asm volatile("isync":::"memory");
	asm volatile("slbmte  %0,%0"::"r" (0) : "memory");
	asm volatile("isync; slbia; isync":::"memory");
	create_shadowed_slbe(PAGE_OFFSET, mmu_kernel_ssize, lflags, LINEAR_INDEX);
	create_shadowed_slbe(H_VMALLOC_START, mmu_kernel_ssize, vflags, VMALLOC_INDEX);

	/* For the boot cpu, we're running on the stack in init_thread_union,
	 * which is in the first segment of the linear mapping, and also
	 * get_paca()->kstack hasn't been initialized yet.
	 * For secondary cpus, we need to bolt the kernel stack entry now.
	 */
	slb_shadow_clear(KSTACK_INDEX);
	if (raw_smp_processor_id() != boot_cpuid &&
	    (get_paca()->kstack & slb_esid_mask(mmu_kernel_ssize)) > PAGE_OFFSET)
		create_shadowed_slbe(get_paca()->kstack,
				     mmu_kernel_ssize, lflags, KSTACK_INDEX);

	asm volatile("isync":::"memory");
}

#define ESID_256M_STEG_MASK ((1UL << (35 + SEGTB_SIZE_SHIFT  - 43 + 1)) - 1)
#define ESID_1T_STEG_MASK ((1UL << (23 + SEGTB_SIZE_SHIFT - 31  + 1)) - 1)

static inline bool seg_entry_valid(struct seg_entry *entry)
{
	return !!(be64_to_cpu(entry->ste_e) & STE_VALID);
}

static inline bool seg_entry_bolted(struct seg_entry *entry)
{
	return !!(be64_to_cpu(entry->ste_v) & STE_BOLTED);
}

static inline bool seg_entry_match(struct seg_entry *entry, unsigned long esid)
{
	unsigned long ste_esid;

	ste_esid = be64_to_cpu(entry->ste_e) >> PPC_BITLSHIFT(35);
	if (ste_esid == esid)
		return true;
	return false;
}

#define STE_PER_STEG 8
static inline bool ste_present(unsigned long seg_table, unsigned long ste_group,
			       unsigned long esid)
{
	int i;
	struct seg_entry *entry;

	entry = (struct seg_entry *)(seg_table + (ste_group << 7));
	for (i = 0; i < STE_PER_STEG; i++) {
		if (seg_entry_valid(entry) && seg_entry_match(entry, esid))
			return true;
		entry++;
	}
	return false;
}

static inline struct seg_entry *get_free_ste(unsigned long seg_table,
					     unsigned long ste_group)
{
	int i;
	struct seg_entry *entry;

	entry = (struct seg_entry *)(seg_table + (ste_group << 7));
	for (i = 0; i < STE_PER_STEG; i++) {
		if (!seg_entry_valid(entry))
			return entry;
		entry++;
	}
	return NULL;

}

static struct seg_entry *get_random_ste(unsigned long seg_table,
					unsigned long ste_group)
{
	int i;
	struct seg_entry *entry;

again:
	/* Randomly pick a slot */
	i = mftb() & 0x7;

	/* randomly pick pimary or secondary */
	if (mftb() & 0x1)
		ste_group = ~ste_group;

	entry = (struct seg_entry *)(seg_table + (ste_group << 7));
	if (seg_entry_bolted(entry + i))
		goto again;

	return entry + i;

}
static void do_segment_load(unsigned long seg_table, unsigned long ea,
			    unsigned long vsid, int ssize, int psize,
			    unsigned long protection, bool bolted)
{
	unsigned long esid;
	unsigned long ste_group;
	struct seg_entry *entry;
	unsigned long ste_e, ste_v;

	if (ssize == MMU_SEGSIZE_256M) {
		esid = GET_ESID(ea);
		ste_group = esid &  ESID_256M_STEG_MASK;
	} else {
		esid = GET_ESID_1T(ea);
		ste_group = esid &  ESID_1T_STEG_MASK;
	}

	if (ste_present(seg_table, ste_group, esid))
		return;
	/*
	 * check the secondary
	 */
	if (ste_present(seg_table, ~ste_group, esid))
		return;

	/*
	 * search for a free slot in primary
	 */

	entry = get_free_ste(seg_table, ste_group);
	if (!entry) {
		/* seach the secondary */
		entry = get_free_ste(seg_table, ~ste_group);
		if (!entry) {
			entry = get_random_ste(seg_table, ste_group);
			if (!entry)
				return;
		}
	}
	/*
	 * update the valid bit to 0, FIXME!! Do we need
	 * to do a translation cache invalidation for the entry we
	 * are stealing ? The translation is still valid.
	 */
	entry->ste_e &= ~cpu_to_be64(STE_VALID);
	/*
	 * Make sure everybody see the valid bit cleared, before they
	 * see the update to other part of ste.
	 */
	smp_mb();

	ste_v = (unsigned long)ssize << PPC_BITLSHIFT(65- 64);
	ste_v |= (vsid << (PPC_BITLSHIFT(115 - 64) + (SID_SHIFT_1T - SID_SHIFT)));
	/*
	 * The sllp value is an already shifted value with right bit
	 * positioning.
	 */
	ste_v |= mmu_psize_defs[psize].sllp;
	ste_v |= protection;

	if (bolted)
		ste_v  |= STE_BOLTED;


	ste_e = esid << segment_shift(ssize);
	ste_e |=  STE_VALID;

	entry->ste_v = cpu_to_be64(ste_v);
	/*
	 * Make sure we have rest of values updated before marking the
	 * ste entry valid
	 */
	smp_mb();
	entry->ste_e = cpu_to_be64(ste_e);
}

static inline void __segment_load(mm_context_t *context, unsigned long ea,
				  unsigned long vsid, int ssize, int psize,
				  unsigned long protection, bool bolted)
{
	/*
	 * Take the lock and check again if somebody else inserted
	 * segment entry meanwhile. if so return
	 */
	spin_lock(context->seg_tbl_lock);

	do_segment_load(context->seg_table, ea, vsid, ssize, psize,
			protection, bolted);
	spin_unlock(context->seg_tbl_lock);
}

static void segment_table_load(unsigned long ea)
{
	int ssize, psize;
	unsigned long vsid;
	unsigned long protection;
	struct mm_struct *mm = current->mm;

	if (!mm)
		BUG();
	/*
	 * We won't get segment fault for kernel mapping here, because
	 * we bolt them all during task creation.
	 */
	switch(REGION_ID(ea)) {
	case H_USER_REGION_ID:
		psize = get_slice_psize(mm, ea);
		ssize = user_segment_size(ea);
		vsid = get_vsid(mm->context.id, ea, ssize);
		protection = SLB_VSID_USER;
		break;
	default:
		pr_err("We should not get slb fault on EA %lx\n", ea);
		return;
	}
	return __segment_load(&mm->context, ea, vsid, ssize, psize,
			      protection, false);
}

void handle_slb_miss(struct pt_regs *regs,
		     unsigned long address, unsigned long trap)
{
	enum ctx_state prev_state = exception_enter();

	if (mmu_has_feature(MMU_FTR_SEG_TABLE))
		segment_table_load(address);
	else
		slb_allocate(address);
	exception_exit(prev_state);
}


static inline void insert_1T_segments(unsigned long seg_table, unsigned long start)
{
	int i;
	unsigned long vsid;
	/* FIXME psize */
	unsigned long psize = mmu_linear_psize;


	for (i = 0; i < 64; i++)
	{
		vsid = get_kernel_vsid(start, MMU_SEGSIZE_1T);
		do_segment_load(seg_table, start, vsid, MMU_SEGSIZE_1T, psize,
				SLB_VSID_KERNEL, true);
		start += 1UL << 40;
	}
}

static inline void segtbl_insert_kernel_mapping(unsigned long seg_table)
{
	/*
	 * insert mapping for the full kernel. Map the entire kernel with 1TB segments
	 * and we create mapping for max possible memory supported which at this
	 * point is 64TB.
	 */
	insert_1T_segments(seg_table, 0xC000000000000000UL);
	insert_1T_segments(seg_table, 0xD000000000000000UL);
	insert_1T_segments(seg_table, 0xF000000000000000UL);
	/*
	 * now insert a 256MB segment for address zero. We want to handle
	 * acess to NULL via pagefault handler
	 */
	do_segment_load(seg_table, 0, 0, MMU_SEGSIZE_256M, mmu_linear_psize, SLB_VSID_KERNEL, true);

}

#define PGALLOC_GFP GFP_KERNEL | __GFP_NOTRACK | __GFP_REPEAT | __GFP_ZERO
unsigned long __init_refok segment_table_initialize(struct prtb_entry *prtb)
{
	unsigned long seg_table;
	unsigned long seg_tb_vsid;
	unsigned long seg_tb_vpn;
	unsigned long segtb_size = 1UL<< SEGTB_SIZE_SHIFT;
	/*
	 * Fill in the process table.
	 * For now allocate 64K segment table.
	 */
	if (slab_is_available()) {
		struct page *page;
		page = alloc_pages(PGALLOC_GFP, SEGTB_SIZE_SHIFT - PAGE_SHIFT);
		if (!page)
			return -ENOMEM;
		seg_table = (unsigned long)page_address(page);
	} else {
		seg_table = (unsigned long)__va(memblock_alloc_base(segtb_size, segtb_size,
						     MEMBLOCK_ALLOC_ANYWHERE));
		memset((void *)seg_table, 0, segtb_size);
	}
	pr_err("Allocating segment table at %p\n", (void *)seg_table);
	/*
	 * Now fill with kernel mappings
	 */
	segtbl_insert_kernel_mapping(seg_table);
	seg_tb_vsid = get_kernel_vsid(seg_table, mmu_kernel_ssize);
	/*
	 * our vpn shift is 12, so we can use the same function. lucky
	 */
	BUILD_BUG_ON_MSG(12 != VPN_SHIFT, "VPN_SHIFT is not 12");
	seg_tb_vpn = hpt_vpn(seg_table, seg_tb_vsid, mmu_kernel_ssize);
	/*
	 * segment size
	 */
	prtb->prtb0 = (unsigned long)mmu_kernel_ssize << PPC_BITLSHIFT(1);
	/*
	 * seg table vpn already ignore the lower 12 bits of the virtual
	 * address and is exactly STABORGU || STABORGL.
	 */
	prtb->prtb0 |= seg_tb_vpn >> 4 ;
	prtb->prtb1 = (seg_tb_vpn & 0xf) << PPC_BITLSHIFT(3);
	/*
	 * stps field
	 */
	prtb->prtb1 |= mmu_psize_defs[mmu_linear_psize].sllp << PPC_BITLSHIFT(62);
	/*
	 * set segment table size and valid bit
	 */
	prtb->prtb1 |= ((SEGTB_SIZE_SHIFT - 12) << PPC_BITLSHIFT(59) | 0x1);

	pr_err("Updating process table entry %p\n", prtb);
	return seg_table;
}
