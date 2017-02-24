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

struct vcoproc_instance;
struct vgx6xxx_info;

/* must be called after page catalog is set up
 * return value:
 *  RGX_FIRMWARE_HEAP_BASE's mfn on success
 *  INVALID_MFN on failure
 */
mfn_t gx6xxx_mmu_init(struct vcoproc_instance *vcoproc,
                      struct vgx6xxx_info *vinfo);

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

#endif /* __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COMMON_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
