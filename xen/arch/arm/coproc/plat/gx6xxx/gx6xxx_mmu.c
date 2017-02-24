/*
 * xen/arch/arm/coproc/plat/gx6xxx/gx6xxx_mmu.c
 *
 * GX6XXX MMU code
 *
 * Oleksandr Andrushchenko <oleksandr_andrushchenko@epam.com>
 * Copyright (C) 2017 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "gx6xxx_coproc.h"
#include "gx6xxx_hexdump.h"
#include "gx6xxx_mmu.h"
#include "rgx_meta.h"
#include "rgxmmudefs_km.h"

/* Setup of Px Entries:
 *
 *
 * PAGE TABLE (8 Byte):
 *
 * | 62              | 61...40         | 39...12 (varies) | 11...6          | 5             | 4      | 3               | 2               | 1         | 0     |
 * | PM/Meta protect | VP Page (39:18) | Physical Page    | VP Page (17:12) | Entry Pending | PM src | SLC Bypass Ctrl | Cache Coherency | Read Only | Valid |
 *
 *
 * PAGE DIRECTORY (8 Byte):
 *
 *  | 40            | 39...5  (varies)        | 4          | 3...1     | 0     |
 *  | Entry Pending | Page Table base address | (reserved) | Page Size | Valid |
 *
 *
 * PAGE CATALOGUE (4 Byte):
 *
 *  | 31...4                      | 3...2      | 1             | 0     |
 *  | Page Directory base address | (reserved) | Entry Pending | Valid |
 *
 */

static inline uint64_t get_pd_addr(uint32_t pce)
{
    if ( unlikely(!(pce & RGX_MMUCTRL_PC_DATA_VALID_EN)) )
        return 0;
    return (pce >> RGX_MMUCTRL_PC_DATA_PD_BASE_SHIFT) << PAGE_SHIFT;
}

static inline uint64_t get_pt_addr_and_order(uint64_t pde, int *order)
{
    if ( unlikely(!(pde & RGX_MMUCTRL_PD_DATA_VALID_EN)) )
        return 0;
    *order = (pde & ~RGX_MMUCTRL_PD_DATA_PAGE_SIZE_CLRMSK) >> RGX_MMUCTRL_PD_DATA_PAGE_SIZE_SHIFT;
    return pde & ~RGX_MMUCTRL_PD_DATA_PT_BASE_CLRMSK;
}

static inline uint64_t get_pte_addr(uint64_t pte)
{
    if ( unlikely(!(pte & RGX_MMUCTRL_PT_DATA_VALID_EN)) )
        return 0;
    return pte & ~RGX_MMUCTRL_PT_DATA_PAGE_CLRMSK;
}

/* get index in the PC for the device virtual address */
static inline int vaddr_to_pce_idx(uint64_t vaddr)
{
    return (vaddr & ~RGX_MMUCTRL_VADDR_PC_INDEX_CLRMSK) >> RGX_MMUCTRL_VADDR_PC_INDEX_SHIFT;
}

/* get index in the PD for the device virtual address */
static inline int vaddr_to_pde_idx(uint64_t vaddr)
{
    return (vaddr & ~RGX_MMUCTRL_VADDR_PD_INDEX_CLRMSK) >> RGX_MMUCTRL_VADDR_PD_INDEX_SHIFT;
}

/* get index in the PT for the device virtual address */
static inline int vaddr_to_pte_idx(uint64_t vaddr)
{
    return (vaddr & ~RGX_MMUCTRL_VADDR_PT_INDEX_CLRMSK) >> RGX_MMUCTRL_VADDR_PT_INDEX_SHIFT;
}

mfn_t gx6xxx_mmu_devaddr_to_mfn(struct vcoproc_instance *vcoproc,
                                struct vgx6xxx_info *vinfo, uint64_t dev_vaddr)
{
    int idx, order;
    mfn_t mfn;
    uint64_t *pg64;
    uint64_t ipa;

    printk("%s dev_vaddr %lx\n", __FUNCTION__, dev_vaddr);
    /* get index in the page directory */
    idx = vaddr_to_pde_idx(dev_vaddr);
    BUG_ON(idx >= RGX_MMUCTRL_ENTRIES_PD_VALUE);
    pg64 = (uint64_t *)map_domain_page(vinfo->mfn_pd);
    if ( unlikely(!pg64) )
    {
        printk("Failed to map page directory MFN %lx\n", vinfo->mfn_pd);
        return INVALID_MFN;
    }
    printk("Page directory MFN %lx\n", vinfo->mfn_pd);
    gx6xxx_dump((uint32_t *)pg64, PAGE_SIZE);
    /* read PT base address */
    ipa = get_pt_addr_and_order(pg64[idx], &order);
    unmap_domain_page(pg64);

    if ( unlikely(!ipa) )
    {
        printk("No valid IPA for page table\n");
        return INVALID_MFN;
    }
    /* FIXME: we only expect 4K pages for now */
    BUG_ON(order != 0);
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    printk("Page table IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        printk("Failed to lookup page table\n");
        return INVALID_MFN;
    }
    /* get index in the page table */
    idx = vaddr_to_pte_idx(dev_vaddr);
    BUG_ON(idx >= RGX_MMUCTRL_ENTRIES_PT_VALUE);
    pg64 = (uint64_t *)map_domain_page(mfn);
    if ( unlikely(!pg64) )
    {
        printk("Failed to map page table MFN %lx\n", mfn);
        return INVALID_MFN;
    }
    gx6xxx_dump((uint32_t *)pg64, PAGE_SIZE);
    /* read PT base address */
    ipa = get_pte_addr(pg64[idx]);
    unmap_domain_page(pg64);

    if ( unlikely(!ipa) )
    {
        printk("No valid IPA for page table entry for vaddr %lx\n",
               dev_vaddr);
        return INVALID_MFN;
    }
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    printk("Page table entry IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        printk("Failed to lookup page table entry for %lx\n",
                dev_vaddr);
        return INVALID_MFN;
    }
    return mfn;
}

mfn_t gx6xxx_mmu_init(struct vcoproc_instance *vcoproc,
                    struct vgx6xxx_info *vinfo)
{
    uint64_t ipa;
    uint32_t *pgc;
    int idx;
    mfn_t mfn;

    vinfo->mfn_pc = INVALID_MFN;
    vinfo->mfn_pd = INVALID_MFN;
    vinfo->mfn_rgx_fwif_init = INVALID_MFN;

    /* FIXME: reg_val_cr_bif_cat_base0 has a physical address of the page
     * catalog (PC) which is one page */
    /* FIXME: only one page must be in PC which is page directory (PD) */
    ipa = vinfo->reg_val_cr_bif_cat_base0.val;
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    printk("Page catalog IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        printk("Failed to lookup page catalog\n");
        return INVALID_MFN;
    }
    /* get index in the page catalog */
    idx = vaddr_to_pce_idx(RGX_FIRMWARE_HEAP_BASE);
    BUG_ON(idx >= RGX_MMUCTRL_ENTRIES_PC_VALUE);
    pgc = (uint32_t *)map_domain_page(mfn);
    if ( unlikely(!pgc) )
    {
        printk("Failed to map page catalog MFN %lx\n", mfn);
        return INVALID_MFN;
    }
    gx6xxx_dump(pgc, PAGE_SIZE);
    /* read PD base address */
    ipa = get_pd_addr(pgc[idx]);
    unmap_domain_page(pgc);
    vinfo->mfn_pc = mfn;

    if ( unlikely(!ipa) )
    {
        printk("No valid IPA for page directory\n");
        return INVALID_MFN;
    }
    /* we have page catalog entry, so we can read page directory */
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    printk("Page directory IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        printk("Failed to lookup page directory\n");
        return INVALID_MFN;
    }
    vinfo->mfn_pd = mfn;
    return gx6xxx_mmu_devaddr_to_mfn(vcoproc, vinfo, RGX_FIRMWARE_HEAP_BASE);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
