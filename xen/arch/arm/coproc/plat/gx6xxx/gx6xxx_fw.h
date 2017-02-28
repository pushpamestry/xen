/*
 * xen/arch/arm/coproc/plat/gx6xxx/gx6xxx_fw.h
 *
 * Gx6XXX firmware utilities
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

#ifndef __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_FW_H__
#define __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_FW_H__

#include <xen/mm.h>

#include "rgx_fwif.h"
#include "rgx_fwif_km.h"
#include "rgx_meta.h"
#include "rgxmmudefs_km.h"

struct vcoproc_instance;
struct vgx6xxx_info;

int gx6xxx_fw_init(struct vcoproc_instance *vcoproc,
                   struct vgx6xxx_info *vinfo, mfn_t mfn_heap_base);

void gx6xxx_fw_deinit(struct vcoproc_instance *vcoproc,
                      struct vgx6xxx_info *vinfo);

void gx6xxx_dump_kernel_ccb(struct vgx6xxx_info *vinfo);

int gx6xxx_send_kernel_ccb_cmd(struct vcoproc_instance *vcoproc,
                               struct vgx6xxx_info *vinfo,
                               RGXFWIF_KCCB_CMD *cmd, uint32_t cmd_sz);

#endif /* __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_FW_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
