#ifndef _ASM_POWERPC_BOOK3S_64_MMU_H_
#define _ASM_POWERPC_BOOK3S_64_MMU_H_

#ifndef __ASSEMBLY__
/*
 * Page size definition
 *
 *    shift : is the "PAGE_SHIFT" value for that page size
 *    sllp  : is a bit mask with the value of SLB L || LP to be or'ed
 *            directly to a slbmte "vsid" value
 *    penc  : is the HPTE encoding mask for the "LP" field:
 *
 */
struct mmu_psize_def
{
	unsigned int	shift;	/* number of bits */
	int		penc[MMU_PAGE_COUNT];	/* HPTE encoding */
	unsigned int	tlbiel;	/* tlbiel supported for that page size */
	unsigned long	avpnm;	/* bits to mask out in AVPN in the HPTE */
	unsigned long	sllp;	/* SLB L||LP (exact mask to use in slbmte) */
};
extern struct mmu_psize_def mmu_psize_defs[MMU_PAGE_COUNT];
/*
 * Add this for now. We will properly start detecting radix once we have
 * all needed bits in place
 */
#define radix_enabled() mmu_has_feature(MMU_FTR_RADIX)

#endif /* __ASSEMBLY__ */

/* 64-bit classic hash table MMU */
#include <asm/book3s/64/mmu-hash.h>
#include <asm/book3s/64/mmu-radix.h>

#ifndef __ASSEMBLY__

typedef unsigned long mm_context_id_t;
struct spinlock;

typedef struct {
	mm_context_id_t id;
	u16 user_psize;		/* page size index */

#ifdef CONFIG_PPC_MM_SLICES
	u64 low_slices_psize;	/* SLB page size encodings */
	unsigned char high_slices_psize[SLICE_ARRAY_SIZE];
#else
	u16 sllp;		/* SLB page size encoding */
#endif
	unsigned long vdso_base;
#ifdef CONFIG_PPC_SUBPAGE_PROT
	struct subpage_prot_table spt;
#endif /* CONFIG_PPC_SUBPAGE_PROT */
#ifdef CONFIG_PPC_ICSWX
	struct spinlock *cop_lockp; /* guard acop and cop_pid */
	unsigned long acop;	/* mask of enabled coprocessor types */
	unsigned int cop_pid;	/* pid value used with coprocessors */
#endif /* CONFIG_PPC_ICSWX */
#ifdef CONFIG_PPC_64K_PAGES
	/* for 4K PTE fragment support */
	void *pte_frag;
#endif
#ifdef CONFIG_SPAPR_TCE_IOMMU
	struct list_head iommu_group_mem_list;
#endif
} mm_context_t;

/*
 * The current system page and segment sizes
 */
extern int mmu_linear_psize;
extern int mmu_virtual_psize;
extern int mmu_vmalloc_psize;
extern int mmu_vmemmap_psize;
extern int mmu_io_psize;

/* MMU initialization */
extern void hlearly_init_mmu(void);
extern void rearly_init_mmu(void);
static inline void early_init_mmu(void)
{
	if (radix_enabled())
		return rearly_init_mmu();
	return hlearly_init_mmu();
}
extern void hlearly_init_mmu_secondary(void);
extern void rearly_init_mmu_secondary(void);
static inline void early_init_mmu_secondary(void)
{
	if (radix_enabled())
		return rearly_init_mmu_secondary();
	return hlearly_init_mmu_secondary();
}

extern void hlsetup_initial_memory_limit(phys_addr_t first_memblock_base,
					 phys_addr_t first_memblock_size);
extern void rsetup_initial_memory_limit(phys_addr_t first_memblock_base,
					 phys_addr_t first_memblock_size);
static inline void setup_initial_memory_limit(phys_addr_t first_memblock_base,
					      phys_addr_t first_memblock_size)
{
	if (radix_enabled())
		return rsetup_initial_memory_limit(first_memblock_base,
						   first_memblock_size);
	return hlsetup_initial_memory_limit(first_memblock_base,
					   first_memblock_size);
}
#endif /* __ASSEMBLY__ */
#endif /* _ASM_POWERPC_BOOK3S_64_MMU_H_ */
