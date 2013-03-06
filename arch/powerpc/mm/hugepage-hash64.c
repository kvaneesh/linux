/*
 * Copyright IBM Corporation, 2013
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
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
#include <linux/mm.h>
#include <asm/machdep.h>

/*
 * The linux hugepage PMD now include the pmd entries followed by the address
 * to the stashed pgtable_t. The stashed pgtable_t contains the hpte bits.
 * [ secondary group | 3 bit hidx | valid ]. We use one byte per each HPTE entry.
 * With 16MB hugepage and 64K HPTE we need 256 entries and with 4K HPTE we need
 * 4096 entries. Both will fit in a 4K pgtable_t.
 */
int __hash_page_thp(unsigned long ea, unsigned long access, unsigned long vsid,
		    pmd_t *pmdp, unsigned long trap, int local, int ssize,
		    unsigned int psize)
{
	unsigned int index, valid;
	unsigned char *hpte_slot_array;
	unsigned long rflags, pa, hidx;
	unsigned long old_pmd, new_pmd;
	int ret, lpsize = MMU_PAGE_16M;
	unsigned long vpn, hash, shift, slot;

	/*
	 * atomically mark the linux large page PMD busy and dirty
	 */
	do {
		old_pmd = pmd_val(*pmdp);
		/* If PMD busy, retry the access */
		if (unlikely(old_pmd & PMD_HUGE_BUSY))
			return 0;
		/* If PMD permissions don't match, take page fault */
		if (unlikely(access & ~old_pmd))
			return 1;
		/*
		 * Try to lock the PTE, add ACCESSED and DIRTY if it was
		 * a write access
		 */
		new_pmd = old_pmd | PMD_HUGE_BUSY | PMD_HUGE_ACCESSED;
		if (access & _PAGE_RW)
			new_pmd |= PMD_HUGE_DIRTY;
	} while (old_pmd != __cmpxchg_u64((unsigned long *)pmdp,
					  old_pmd, new_pmd));
	/*
	 * PP bits. PMD_HUGE_USER is already PP bit 0x2, so we only
	 * need to add in 0x1 if it's a read-only user page
	 */
	rflags = new_pmd & PMD_HUGE_USER;
	if ((new_pmd & PMD_HUGE_USER) && !((new_pmd & PMD_HUGE_RW) &&
					   (new_pmd & PMD_HUGE_DIRTY)))
		rflags |= 0x1;
	/*
	 * PMD_HUGE_EXEC -> HW_NO_EXEC since it's inverted
	 */
	rflags |= ((new_pmd & PMD_HUGE_EXEC) ? 0 : HPTE_R_N);

#if 0 /* FIXME!! */
	if (!cpu_has_feature(CPU_FTR_COHERENT_ICACHE)) {

		/*
		 * No CPU has hugepages but lacks no execute, so we
		 * don't need to worry about that case
		 */
		rflags = hash_page_do_lazy_icache(rflags, __pte(old_pte), trap);
	}
#endif
	/*
	 * Find the slot index details for this ea, using base page size.
	 */
	shift = mmu_psize_defs[psize].shift;
	index = (ea & (HUGE_PAGE_SIZE - 1)) >> shift;
	BUG_ON(index > 4096);

	vpn = hpt_vpn(ea, vsid, ssize);
	hash = hpt_hash(vpn, shift, ssize);
	/*
	 * The hpte hindex are stored in the pgtable whose address is in the
	 * second half of the PMD
	 */
	hpte_slot_array = *(char **)(pmdp + PTRS_PER_PMD);

	valid = hpte_slot_array[index]  & 0x1;
	if (unlikely(valid)) {
		/* update the hpte bits */
		hidx =  hpte_slot_array[index]  >> 1;
		if (hidx & _PTEIDX_SECONDARY)
			hash = ~hash;
		slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
		slot += hidx & _PTEIDX_GROUP_IX;

		ret = ppc_md.hpte_updatepp(slot, rflags, vpn,
					   psize, ssize, local);
		/*
		 * We failed to update, try to insert a new entry.
		 */
		if (ret == -1) {
			/*
			 * large pte is marked busy, so we can be sure
			 * nobody is looking at hpte_slot_array. hence we can
			 * safely update this here.
			 */
			hpte_slot_array[index] = 0;
			valid = 0;
		}
	}

	if (likely(!valid)) {
		unsigned long hpte_group;

		/* insert new entry */
		pa = pmd_pfn(__pmd(old_pmd)) << PAGE_SHIFT;
repeat:
		hpte_group = ((hash & htab_hash_mask) * HPTES_PER_GROUP) & ~0x7UL;

		/* clear the busy bits and set the hash pte bits */
		new_pmd = (new_pmd & ~PMD_HUGE_HPTEFLAGS) | PMD_HUGE_HASHPTE;

		/*
		 * WIMG bits.
		 * We always have _PAGE_COHERENT enabled for system RAM
		 */
		rflags |= _PAGE_COHERENT;

		if (new_pmd & PMD_HUGE_SAO)
			rflags |= _PAGE_SAO;

		/* Insert into the hash table, primary slot */
		slot = ppc_md.hpte_insert(hpte_group, vpn, pa, rflags, 0,
					  psize, lpsize, ssize);
		/*
		 * Primary is full, try the secondary
		 */
		if (unlikely(slot == -1)) {
			hpte_group = ((~hash & htab_hash_mask) *
				      HPTES_PER_GROUP) & ~0x7UL;
			slot = ppc_md.hpte_insert(hpte_group, vpn, pa,
						  rflags, HPTE_V_SECONDARY,
						  psize, lpsize, ssize);
			if (slot == -1) {
				if (mftb() & 0x1)
					hpte_group = ((hash & htab_hash_mask) *
						      HPTES_PER_GROUP) & ~0x7UL;

				ppc_md.hpte_remove(hpte_group);
				goto repeat;
			}
		}
		/*
		 * Hypervisor failure. Restore old pmd and return -1
		 * similar to __hash_page_*
		 */
		if (unlikely(slot == -2)) {
			*pmdp = __pmd(old_pmd);
			hash_failure_debug(ea, access, vsid, trap, ssize,
					   psize, lpsize, old_pmd);
			return -1;
		}
		/*
		 * large pte is marked busy, so we can be sure
		 * nobody is looking at hpte_slot_array. hence we can
		 * safely update this here.
		 */
		hpte_slot_array[index] = slot << 1 | 0x1;
	}
	/*
	 * No need to use ldarx/stdcx here
	 */
	*pmdp = __pmd(new_pmd & ~PMD_HUGE_BUSY);
	return 0;
}
