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

#include <xen/domain_page.h>

#include "gx6xxx_coproc.h"
#include "gx6xxx_mmu.h"
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

/* FIXME: PCE is 4 bytes */
#define PCE_SIZE    sizeof(uint32_t)
/* FIXME: PDE is 8 bytes */
#define PDE_SIZE    sizeof(uint64_t)
/* FIXME: PTE is 8 bytes */
#define PTE_SIZE    sizeof(uint64_t)

static inline uint32_t get_pgd(uint32_t pce)
{
    if ( likely(!(pce & RGX_MMUCTRL_PC_DATA_VALID_EN)) )
        return 0;
    return (pce >> RGX_MMUCTRL_PC_DATA_PD_BASE_SHIFT) << PAGE_SHIFT;
}

static inline uint64_t get_pgt(uint64_t pde)
{
    if ( likely(!(pde & RGX_MMUCTRL_PD_DATA_VALID_EN)) )
        return 0;
    return pde & ~RGX_MMUCTRL_PD_DATA_PT_BASE_CLRMSK;
}

static inline int get_pgt_size(uint64_t pde)
{
    if ( likely(!(pde & RGX_MMUCTRL_PD_DATA_VALID_EN)) )
        return 0;
    return (pde & ~RGX_MMUCTRL_PD_DATA_PAGE_SIZE_CLRMSK) >> RGX_MMUCTRL_PD_DATA_PAGE_SIZE_SHIFT;
}

static inline uint64_t get_pte_addr(uint64_t pte)
{
    if ( likely(!(pte & RGX_MMUCTRL_PT_DATA_VALID_EN)) )
        return 0;
    return pte & ~RGX_MMUCTRL_PT_DATA_PAGE_CLRMSK;
}

void gx6xxx_mmu_shared_page_find(struct vcoproc_instance *vcoproc,
                                 struct vgx6xxx_info *vinfo)
{
    int pc_idx;
    uint32_t *pc, *pce;
    uint64_t ipa;
    mfn_t mfn;

    /* FIXME: reg_val_cr_bif_cat_base0 has a physical address of the page
     * catalog (PC) which is one page */
    /* FIXME: only one page must be in PC which is page directory (PD) */

    ipa = vinfo->reg_val_cr_bif_cat_base0.val;
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    printk("Page catalog IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        printk("Failed to lookup BIF catalog base address\n");
        return;
    }
    pc = (uint32_t *)map_domain_page(mfn);
    if ( unlikely(!pc) )
    {
        printk("Failed to map page catalog\n");
        goto out;
    }
    pce = pc;
    for (pc_idx = 0; pc_idx < PAGE_SIZE/PCE_SIZE; pc_idx++)
    {
        uint32_t pd_ipa;

        pd_ipa = get_pgd(*pce++);
        if ( pd_ipa )
        {
            uint64_t *pd, *pde;
            int pd_idx;

            mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(pd_ipa)), NULL);
            printk("Page directory IPA %x MFN %lx\n", pd_ipa, mfn);
            if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
            {
                printk("Failed to lookup page directory address\n");
                return;
            }
            pd = (uint64_t *)map_domain_page(mfn);
            if ( unlikely(!pd) )
            {
                printk("Failed to map page directory\n");
                goto out;
            }
            pde = pd;
            for (pd_idx = 0; pd_idx < PAGE_SIZE/PDE_SIZE; pd_idx++)
            {
                uint64_t pt_ipa;
                uint64_t *pt, *pte;
                int pt_idx;

                pt_ipa = get_pgt(*pde++);
                if ( pt_ipa )
                {
                    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(pt_ipa)), NULL);
                    printk("Page table IPA %lx MFN %lx\n", pt_ipa, mfn);
                    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
                    {
                        printk("Failed to lookup page table address\n");
                        return;
                    }
                    pt = (uint64_t *)map_domain_page(mfn);
                    if ( unlikely(!pt) )
                    {
                        printk("Failed to map page table\n");
                        goto out;
                    }
                    pte = pt;
                    for (pt_idx = 0; pt_idx < PAGE_SIZE/PTE_SIZE; pt_idx++)
                    {
                        uint64_t paddr = get_pte_addr(*pte++);
                        if ( paddr )
                            printk("paddr %lx\n", paddr);
                    }
                    unmap_domain_page(pt);
                }
            }
            unmap_domain_page(pd);
            break;
        }
    }
out:
    if (pc)
        unmap_domain_page(pc);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
