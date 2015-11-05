#ifndef _ASM_POWERPC_PGTABLE_RADIX_4K_H
#define _ASM_POWERPC_PGTABLE_RADIX_4K_H

/*
 * For 4K page size supported index is 13/9/9/9
 */
#define RPTE_INDEX_SIZE  9  /* 2MB huge page */
#define RPMD_INDEX_SIZE  9  /* 1G huge page */
#define RPUD_INDEX_SIZE	 9
#define RPGD_INDEX_SIZE  13

#endif /* _ASM_POWERPC_PGTABLE_RADIX_4K_H */
