/*
 *  MMU context allocation for radix kernels.
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
#include <linux/idr.h>

#include <asm/mmu_context.h>
#include <asm/book3s/64/mmu-radix.h>
#include <asm/book3s/64/radix.h>

/*
 * We have 64k process table and we need 16 bytes per each pid
 * hence we can have a max of 4K pid.
 */
#define MAX_USER_RADIX_CONTEXT  (1 << (PRTB_SIZE_SHIFT - 4))

static DEFINE_SPINLOCK(mmu_context_lock);
static DEFINE_IDA(mmu_context_ida);

int __rinit_new_context(void)
{
	int index;
	int err;

again:
	if (!ida_pre_get(&mmu_context_ida, GFP_KERNEL))
		return -ENOMEM;

	spin_lock(&mmu_context_lock);
	err = ida_get_new_above(&mmu_context_ida, 1, &index);
	spin_unlock(&mmu_context_lock);

	if (err == -EAGAIN)
		goto again;
	else if (err)
		return err;

	if (index > MAX_USER_RADIX_CONTEXT) {
		spin_lock(&mmu_context_lock);
		ida_remove(&mmu_context_ida, index);
		spin_unlock(&mmu_context_lock);
		return -ENOMEM;
	}

	return index;
}
EXPORT_SYMBOL_GPL(__rinit_new_context);

int rinit_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
	int index;
	unsigned long rts_field;

	index = __init_new_context();
	if (index < 0)
		return index;

	mm->context.id = index;
	/*
	 * set the process table entry,
	 */
	rts_field = 3ull << PPC_BITLSHIFT(2);
	process_tb[index].prtb0 = cpu_to_be64(rts_field | __pa(mm->pgd) | RPGD_INDEX_SIZE);
	return 0;
}

void __rdestroy_context(int context_id)
{
	spin_lock(&mmu_context_lock);
	ida_remove(&mmu_context_ida, context_id);
	spin_unlock(&mmu_context_lock);
}
EXPORT_SYMBOL_GPL(__rdestroy_context);

void rdestroy_context(struct mm_struct *mm)
{
	process_tb[mm->context.id].prtb1 = 0;
	__destroy_context(mm->context.id);
	mm->context.id = MMU_NO_CONTEXT;
}

void switch_radix_mmu_context(struct mm_struct *prev, struct mm_struct *next)
{
	/*
	 * FIXME!! do we need hard disable irq ?
	 */
	mtspr(SPRN_PID, next->context.id);
	asm volatile("isync": : :"memory");

}
