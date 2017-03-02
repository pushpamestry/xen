/*
 * xen/arch/arm/coproc/plat/gx6xxx/gx6xxx_coproc.h
 *
 * COPROC GPU GX6XXX platform specific code
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

#ifndef __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COPROC_H__
#define __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COPROC_H__

#include <asm/io.h>
#include <xen/atomic.h>

#include "../../coproc.h"
#include "../common.h"

#include "gx6xxx_fw.h"

enum vgx6xxx_state
{
    /* initialization sequence has started - collecting register values
     * so those can be used for real GPU initialization */
    VGX6XXX_STATE_INITIALIZING,
    /* scheduler is running, at least one context switch was made */
    VGX6XXX_STATE_RUNNING,
    /* asked to switch from but waiting for GPU to finish current jobs */
    VGX6XXX_STATE_IN_TRANSIT,
    /* context is off - queueing requests and interrupts */
    VGX6XXX_STATE_WAITING,
};
#define VGX6XXX_STATE_DEFAULT   VGX6XXX_STATE_INITIALIZING

union reg64_t
{
    struct
    {
        uint32_t lo;
        uint32_t hi;
    } as;
    uint64_t val;
};

struct vgx6xxx_info
{
    /* current state of the vcoproc */
    enum vgx6xxx_state state;

    /* set if scheduler has been started for this vcoproc */
    bool scheduler_started;

    /* number of IRQs received - used to check if IRQ expected
     * at "switch from" time
     */
    atomic_t irq_count;

    /* FIXME: the below are frequently used, so they are mapped on
     * vcoproc init and unmapped on deinit
     */
    RGXFWIF_INIT *fw_init;
    RGXFWIF_TRACEBUF *fw_trace_buf;
    IMG_UINT8 *fw_kernel_ccb;
    RGXFWIF_CCB_CTL *fw_kernel_ccb_ctl;
    IMG_UINT8 *fw_firmware_ccb;
    RGXFWIF_CCB_CTL *fw_firmware_ccb_ctl;
    volatile IMG_UINT32 *fw_power_sync;

    /*
     ***************************************************************************
     *                           REGISTERS
     ***************************************************************************
     */
    /* This is the current IRQ status register value reported/updated
     * to/from domains. Set on real IRQ from GPU, low 32-bits
     */
    union reg64_t reg_val_irq_status;
    /* Current value of the soft reset register, used to determine
     * when FW starts to run
     */
    union reg64_t reg_val_cr_soft_reset;

    /* number of writes to RGX_CR_MTS_SCHEDULE while not in running state */
    int reg_cr_mts_schedule_lo_wait_cnt;

    /*
     ***************************************************************************
     * FIXME: Value of the registers below must be saved on write
     ***************************************************************************
     */
    /* FIXME: META boot control register - low 32-bits are used */
    /* FIXME: this must be tracked when written, reset on read */
    union reg64_t reg_val_cr_meta_boot;

    union reg64_t reg_val_cr_mts_garten_wrapper_config;

    /*
     ***************************************************************************
     * FIXME: Value of the registers remain constant once written
     * and can be read back
     ***************************************************************************
     */
    /* FIXME: SLC control register - low 32-bits are used */
    union reg64_t reg_val_cr_slc_ctrl_misc;
    union reg64_t reg_val_cr_axi_ace_lite_configuration;
    /* FIXME: address of kernel page catalog, MMU PC
     * FIXME: PD and PC are fixed size and can't be larger than page size
     */
    union reg64_t reg_val_cr_bif_cat_base0;

    /*
     ***************************************************************************
     *                           Gx6XXX MMU
     ***************************************************************************
     */
    /* page catalog */
    mfn_t mfn_pc;
    /* page directory */
    mfn_t mfn_pd;
};

#ifdef GX6XXX_DEBUG
void gx6xxx_print_reg(const char *prefix, uint32_t reg, uint32_t val);
#else
#define gx6xxx_print_reg(a, b, c) {}
#endif

#define REG_LO32(a) ( (a) )
#define REG_HI32(a) ( (a) + sizeof(uint32_t) )

static inline uint32_t gx6xxx_read32(struct coproc_device *coproc,
                                     uint32_t offset)
{
#ifdef GX6XXX_DEBUG
    uint32_t val = readl((char *)coproc->mmios[0].base + offset);

    gx6xxx_print_reg(__FUNCTION__, offset, val);
    return val;
#else
    return readl((char *)coproc->mmios[0].base + offset);
#endif
}

static inline void gx6xxx_write32(struct coproc_device *coproc,
                                  uint32_t offset, uint32_t val)
{
    gx6xxx_print_reg(__FUNCTION__, offset, val);
    writel(val, (char *)coproc->mmios[0].base + offset);
}

static inline uint64_t gx6xxx_read64(struct coproc_device *coproc,
                                     uint32_t offset)
{
#ifdef GX6XXX_DEBUG
    uint64_t val = readq((char *)coproc->mmios[0].base + offset);

    gx6xxx_print_reg(__FUNCTION__, REG_LO32(offset), val & 0xffffffff);
    gx6xxx_print_reg(__FUNCTION__, REG_HI32(offset), val >> 32);
    return val;
#else
    return readq((char *)coproc->mmios[0].base + offset);
#endif
}

static inline void gx6xxx_write64(struct coproc_device *coproc,
                                  uint32_t offset, uint64_t val)
{
    gx6xxx_print_reg(__FUNCTION__, REG_LO32(offset), val & 0xffffffff);
    gx6xxx_print_reg(__FUNCTION__, REG_HI32(offset), val >> 32);
    writeq(val, (char *)coproc->mmios[0].base + offset);
}

#endif /* __ARCH_ARM_COPROC_PLAT_GX6XXX_GX6XXX_COPROC_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
