#ifndef _ASM_POWERPC_BOOK3S_64_MMU_RADIX_H_
#define _ASM_POWERPC_BOOK3S_64_MMU_RADIX_H_

#ifndef __ASSEMBLY__

struct prtb_entry {
	__be64 prtb0;
	__be64 prtb1;
};
extern struct prtb_entry *process_tb;

struct patb_entry {
	__be64 patb0;
	__be64 patb1;
};
extern struct patb_entry *partition_tb;

#define PATB_HR		PPC_BIT(0)
#define PATB_GR		PPC_BIT(0)
#define RPDB_MASK	(PPC_BITMASK(3, 55))
#define RPDB_SHIFT	PPC_BITLSHIFT(55)
/*
 * For now we limit both the process table and partition
 * table size to be PAGE_SIZE
 */
#define PRTB_SIZE_SHIFT	PAGE_SHIFT
#define PATB_SIZE_SHIFT	PAGE_SHIFT

extern void radix_init_native(void);
#endif /* !__ASSEMBLY__ */
#endif /*  _ASM_POWERPC_BOOK3S_64_MMU_RADIX_H_ */
