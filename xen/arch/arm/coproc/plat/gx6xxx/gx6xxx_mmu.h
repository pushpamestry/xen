/*
 * xen/arch/arm/coproc/plat/gx6xxx/gx6xxx_mmu.h
 *
 * Gx6XXX MMU handling
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

#ifndef __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COMMON_H__
#define __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COMMON_H__

#include <xen/domain_page.h>
#include <xen/err.h>

#include "rgx_fwif_km.h"

struct vcoproc_instance;
struct vgx6xxx_info;

#define RGXFW_SEGMMU_DATA_CACHE_MASK    (RGXFW_SEGMMU_DATA_BASE_ADDRESS |    \
                                         RGXFW_SEGMMU_DATA_META_CACHED |     \
                                         RGXFW_SEGMMU_DATA_META_UNCACHED |   \
                                         RGXFW_SEGMMU_DATA_VIVT_SLC_CACHED | \
                                         RGXFW_SEGMMU_DATA_VIVT_SLC_UNCACHED)


/* must be called after page catalog is set up
 * return value:
 *  RGX_FIRMWARE_HEAP_BASE's mfn on success
 *  INVALID_MFN on failure
 */
mfn_t gx6xxx_mmu_init(struct vcoproc_instance *vcoproc,
                      struct vgx6xxx_info *vinfo);

static inline uint64_t gx6xxx_mmu_meta_to_dev_vaddr(uint32_t meta_addr)
{
    return (meta_addr & ~RGXFW_SEGMMU_DATA_CACHE_MASK) +
            RGX_FIRMWARE_HEAP_BASE;
}

static inline void *gx6xxx_mmu_map(mfn_t mfn)
{
    void *vaddr = map_domain_page(mfn);
    if ( unlikely(!vaddr) )
    {
        printk("Failed to map page table MFN %lx\n", mfn);
        return ERR_PTR(-EINVAL);
    }
    return vaddr;
}

static inline void gx6xxx_mmu_unmap(void *vaddr)
{
    if ( likely(vaddr) )
        unmap_domain_page(vaddr);
}

mfn_t gx6xxx_mmu_devaddr_to_mfn(struct vcoproc_instance *vcoproc,
                                struct vgx6xxx_info *vinfo, uint64_t dev_vaddr);

#define GX6XXX_MMU_PAGE_OFFSET( a ) (a & ~PAGE_MASK)

static inline paddr_t gx6xxx_mmu_devaddr_to_maddr(struct vcoproc_instance *vcoproc,
                                                  struct vgx6xxx_info *vinfo,
                                                  uint64_t dev_vaddr)
{
    mfn_t mfn;

    mfn = gx6xxx_mmu_devaddr_to_mfn(vcoproc, vinfo, dev_vaddr);
    if ( unlikely(mfn == INVALID_MFN) )
        return 0;
    return pfn_to_paddr(mfn) + GX6XXX_MMU_PAGE_OFFSET(dev_vaddr);
}

#endif /* __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COMMON_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
