#include <xen/delay.h>

#include "gx6xxx_coproc.h"
#include "gx6xxx_fw.h"
#include "gx6xxx_startstop.h"

static inline bool gx6xxx_is_irq_pending(struct gx6xxx_info *info)
{
    uint32_t irq_status;

#if 1
    irq_status = readl(info->reg_vaddr_irq_status);
#else
    irq_status = gx6xxx_read32(coproc, RGXFW_CR_IRQ_STATUS);
#endif
    return irq_status & RGXFW_CR_IRQ_STATUS_EVENT_EN;
}

static int gx6xxx_poll_reg32(struct coproc_device *coproc, uint32_t offset,
                             uint32_t expected, uint32_t mask)
{
    uint32_t val;
    int retry = GX6XXX_POLL_TO_NUM_US;
#ifdef GX6XXX_DEBUG
    bool old_debug = gx6xxx_debug;

    gx6xxx_debug = false;
#endif
    do
    {
        /* read current register value and mask only those bits requested */
        val = gx6xxx_read32(coproc, offset) & mask;
        if ( val == expected )
        {
#ifdef GX6XXX_DEBUG
            gx6xxx_debug = old_debug;
#endif
            return 0;
        }
        cpu_relax();
        udelay(1);
    } while (retry--);
#ifdef GX6XXX_DEBUG
    printk("%s expected %08x got %08x ))))))))))))))))))))))))))))))))))))))))\n",
                    __FUNCTION__, expected, val);
    gx6xxx_debug = old_debug;
#endif
    return -ETIMEDOUT;
}

static int gx6xxx_poll_val32(volatile uint32_t *val, uint32_t expected,
                             uint32_t mask)
{
    int retry = GX6XXX_POLL_TO_NUM_US;
#ifdef GX6XXX_DEBUG
    bool old_debug = gx6xxx_debug;

    gx6xxx_debug = false;
#endif
    do
    {
        if ( (*val & mask) == expected )
        {
#ifdef GX6XXX_DEBUG
            gx6xxx_debug = old_debug;
#endif
            return 0;
        }
        cpu_relax();
        udelay(1);
    } while (retry--);
#ifdef GX6XXX_DEBUG
    printk("%s expected %08x got %08x ))))))))))))))))))))))))))))))))))))))))\n",
                    __FUNCTION__, expected, *val);
    gx6xxx_debug = old_debug;
#endif
    return -ETIMEDOUT;
}

static int gx6xxx_poll_reg64(struct coproc_device *coproc, uint32_t offset,
                             uint64_t expected, uint64_t mask)
{
    uint64_t val;
    int retry = GX6XXX_POLL_TO_NUM_US;
#ifdef GX6XXX_DEBUG
    bool old_debug = gx6xxx_debug;

    gx6xxx_debug = false;
#endif
    do
    {
        /* read current register value and mask only those bits requested */
        val = gx6xxx_read64(coproc, offset) & mask;
        if ( val == expected )
        {
#ifdef GX6XXX_DEBUG
            gx6xxx_debug = old_debug;
#endif
            return 0;
        }
        cpu_relax();
        udelay(1);
    } while (retry--);
#ifdef GX6XXX_DEBUG
    gx6xxx_debug = old_debug;
    printk("%s expected %016lx got %016lx ))))))))))))))))))))))))))))))))))))))))\n",
                    __FUNCTION__, expected, val);
#endif
    return -ETIMEDOUT;
}

static int gx6xxx_write_via_slave_port32(struct coproc_device *coproc,
                                         uint32_t offset, uint32_t val)
{
    int ret;

    /* Wait for Slave Port to be Ready */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_META_SP_MSLVCTRL1,
                          RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN,
                          RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN);
    if ( ret < 0 )
        return ret;

    /* Issue a Write */
    gx6xxx_write32(coproc, RGX_CR_META_SP_MSLVCTRL0, offset);
    gx6xxx_write32(coproc, RGX_CR_META_SP_MSLVDATAT, val);

    return 0;
}

static int gx6xxx_read_via_slave_port32(struct coproc_device *coproc,
                                        uint32_t offset, uint32_t *val)
{
    int ret;

    /* Wait for Slave Port to be Ready */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_META_SP_MSLVCTRL1,
                          RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN,
                          RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN);
    if ( ret < 0 )
        return ret;

    /* Issue a Read */
    gx6xxx_write32(coproc, RGX_CR_META_SP_MSLVCTRL0, offset | RGX_CR_META_SP_MSLVCTRL0_RD_EN);

    /* Wait for Slave Port to be Ready */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_META_SP_MSLVCTRL1,
                          RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN,
                          RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN);
    if ( ret < 0 )
        return ret;

    *val = gx6xxx_read32(coproc, RGX_CR_META_SP_MSLVDATAX);
    return 0;
}

static inline int gx6xxx_wait_fw_started(struct vcoproc_instance *vcoproc,
                                         struct vgx6xxx_info *vinfo,
                                         IMG_BOOL expected)
{
    int ret;

    dev_dbg(vcoproc->coproc->dev, "vinfo->fw_init->bFirmwareStarted %d\n",
            vinfo->fw_init->bFirmwareStarted);
    ret = gx6xxx_poll_val32((volatile IMG_BOOL *)&vinfo->fw_init->bFirmwareStarted,
                            expected, 0xFFFFFFFF);
    dev_dbg(vcoproc->coproc->dev, "vinfo->fw_init->bFirmwareStarted %d\n",
            vinfo->fw_init->bFirmwareStarted);
    return ret;
}

static s_time_t gx6xxx_save_reg_ctx(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    uint32_t offset;
    int i;
#ifdef GX6XXX_DEBUG
    bool old_gx6xxx_debug;

    old_gx6xxx_debug = gx6xxx_debug;
    gx6xxx_debug = false;
#endif
    for (i = 0, offset = 0; i < vinfo->reg_ctx.count;
         i++, offset += sizeof(*vinfo->reg_ctx.regs))
    {
        vinfo->reg_ctx.regs[i].val = gx6xxx_read64(vcoproc->coproc, offset);
        gx6xxx_write64(vcoproc->coproc, offset, 0);
    }
#ifdef GX6XXX_DEBUG
    gx6xxx_debug = old_gx6xxx_debug;
#endif
    return 0;
}

static void gx6xxx_restore_reg_ctx(struct vcoproc_instance *vcoproc,
                                   struct vgx6xxx_info *vinfo)
{
    uint32_t offset;
    int i;
#ifdef GX6XXX_DEBUG
    bool old_gx6xxx_debug;

    old_gx6xxx_debug = gx6xxx_debug;
    gx6xxx_debug = false;
#endif
    for (i = 0, offset = 0; i < vinfo->reg_ctx.count;
         i++, offset += sizeof(*vinfo->reg_ctx.regs))
        gx6xxx_write64(vcoproc->coproc, i * sizeof(*vinfo->reg_ctx.regs),
                       vinfo->reg_ctx.regs[i].val);
#ifdef GX6XXX_DEBUG
    gx6xxx_debug = old_gx6xxx_debug;
#endif
    /* force all clocks on */
    gx6xxx_write64(vcoproc->coproc, RGX_CR_CLK_CTRL, RGX_CR_CLK_CTRL_ALL_ON);
}

static bool gx6xxx_run_if_not_idle_or_off(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;

    if ( unlikely((vinfo->fw_trace_buf->ePowState == RGXFWIF_POW_FORCED_IDLE) ||
                  (vinfo->fw_trace_buf->ePowState == RGXFWIF_POW_OFF)) )
        return false;
    return true;
}

static bool gx6xxx_run_if_not_off(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;

    if ( unlikely(vinfo->fw_trace_buf->ePowState == RGXFWIF_POW_OFF) )
        return false;
    return true;
}

static bool gx6xxx_run_always(struct vcoproc_instance *vcoproc)
{
    return true;
}

static s_time_t gx6xxx_wait_kccb(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    struct gx6xxx_info *info = (struct gx6xxx_info *)vcoproc->coproc->priv;
    int ret;

    ret = gx6xxx_fw_wait_kccb_cmd(vcoproc, vinfo, info->state_kccb_read_ofs);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;
    return 0;
}

static s_time_t gx6xxx_wait_psync(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    int ret, retry = 10;

    /* wait for GPU to finish current workload */
    do
    {
        ret = gx6xxx_poll_val32(vinfo->fw_power_sync, 0x1, 0xFFFFFFFF);
        if ( ret < 0 )
            continue;
    } while (retry--);
    if ( ret < 0 )
        return GX6XXX_WAIT_TIME_US;
    return 0;
}

static s_time_t gx6xxx_force_idle(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    struct gx6xxx_info *info = (struct gx6xxx_info *)vcoproc->coproc->priv;
    RGXFWIF_KCCB_CMD pow_cmd;
    int ret;

    pow_cmd.eDM = RGXFWIF_DM_GP;
    pow_cmd.eCmdType = RGXFWIF_KCCB_CMD_POW;
    pow_cmd.uCmdData.sPowData.ePowType = RGXFWIF_POW_FORCED_IDLE_REQ;
    pow_cmd.uCmdData.sPowData.uPoweReqData.bCancelForcedIdle = IMG_FALSE;

    dev_dbg(vcoproc->coproc->dev, "sending forced idle command\n");

    vinfo->fw_power_sync[0] = 0;
    ret = gx6xxx_fw_send_kccb_cmd(vcoproc, vinfo, &pow_cmd, 1,
                                  &info->state_kccb_read_ofs);
    if ( unlikely(ret < 0) )
        return ret;
    return 0;
}

static s_time_t gx6xxx_force_idle_check(struct vcoproc_instance *vcoproc)
{
    /* we are forcing IDLE state, if FW is not OFF or IDLE, then something
     * goes wrong, Run condition for this check is not IDLE and not OFF,
     * so just return error
     */
    return -EAGAIN;
}

static s_time_t gx6xxx_request_power_off(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    struct gx6xxx_info *info = (struct gx6xxx_info *)vcoproc->coproc->priv;
    RGXFWIF_KCCB_CMD pow_cmd[RGXFWIF_DM_MAX];
    int i, ret;

    /* prepare commands to be sent to the FW */
    for (i = 0; i < ARRAY_SIZE(pow_cmd); i++)
    {
        pow_cmd[i].eCmdType = RGXFWIF_KCCB_CMD_POW;
        pow_cmd[i].uCmdData.sPowData.ePowType = RGXFWIF_POW_OFF_REQ;
        pow_cmd[i].uCmdData.sPowData.uPoweReqData.bForced = IMG_TRUE;
        pow_cmd[i].eDM = i;
    }
    /* prepare to sync with the FW and send out requests */
    vinfo->fw_power_sync[0] = 0;
    ret = gx6xxx_fw_send_kccb_cmd(vcoproc, vinfo,
                                  pow_cmd, ARRAY_SIZE(pow_cmd),
                                  &info->state_kccb_read_ofs);
    if ( unlikely(ret < 0) )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to send power off command to FW\n");
        return ret;
    }
    return 0;
}

static s_time_t gx6xxx_wait_for_interrupts(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    struct gx6xxx_info *info = (struct gx6xxx_info *)vcoproc->coproc->priv;
    int to_us = GX6XXX_POLL_TO_NUM_US;

    while ( (atomic_read(&vinfo->irq_count) !=
             vinfo->fw_trace_buf->aui32InterruptCount[0]) && to_us-- )
    {
        if ( gx6xxx_is_irq_pending(info) )
            return 1;
        cpu_relax();
        udelay(1);
    }
    if (!to_us)
    {
        dev_dbg(vcoproc->coproc->dev, "TIMEDOUT, IRQs: FW %d vs Xen %d\n",
                vinfo->fw_trace_buf->aui32InterruptCount[0],
                atomic_read(&vinfo->irq_count));
        return GX6XXX_WAIT_TIME_US;
    }
    return 0;
}

static s_time_t gx6xxx_wait_for_slc_idle(struct vcoproc_instance *vcoproc)
{
    struct coproc_device *coproc = vcoproc->coproc;
    int ret;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_SIDEKICK_IDLE,
                            RGX_CR_SIDEKICK_IDLE_MASKFULL^(RGX_CR_SIDEKICK_IDLE_GARTEN_EN|RGX_CR_SIDEKICK_IDLE_SOCIF_EN|RGX_CR_SIDEKICK_IDLE_HOSTIF_EN),
                            RGX_CR_SIDEKICK_IDLE_MASKFULL^(RGX_CR_SIDEKICK_IDLE_GARTEN_EN|RGX_CR_SIDEKICK_IDLE_SOCIF_EN|RGX_CR_SIDEKICK_IDLE_HOSTIF_EN));
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_SLC_IDLE,
                            RGX_CR_SLC_IDLE_MASKFULL,
                            RGX_CR_SLC_IDLE_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;
    return 0;
}

static s_time_t gx6xxx_deassoc_threads(struct vcoproc_instance *vcoproc)
{
    struct coproc_device *coproc = vcoproc->coproc;

    gx6xxx_write32(coproc, RGX_CR_MTS_INTCTX_THREAD0_DM_ASSOC,
                   RGX_CR_MTS_INTCTX_THREAD0_DM_ASSOC_DM_ASSOC_CLRMSK
                   & RGX_CR_MTS_INTCTX_THREAD0_DM_ASSOC_MASKFULL);

    gx6xxx_write32(coproc, RGX_CR_MTS_BGCTX_THREAD0_DM_ASSOC,
                   RGX_CR_MTS_BGCTX_THREAD0_DM_ASSOC_DM_ASSOC_CLRMSK
                   & RGX_CR_MTS_BGCTX_THREAD0_DM_ASSOC_MASKFULL);

    gx6xxx_write32(coproc, RGX_CR_MTS_INTCTX_THREAD1_DM_ASSOC,
                   RGX_CR_MTS_INTCTX_THREAD1_DM_ASSOC_DM_ASSOC_CLRMSK
                   & RGX_CR_MTS_INTCTX_THREAD1_DM_ASSOC_MASKFULL);

    gx6xxx_write32(coproc, RGX_CR_MTS_BGCTX_THREAD1_DM_ASSOC,
                   RGX_CR_MTS_BGCTX_THREAD1_DM_ASSOC_DM_ASSOC_CLRMSK
                   & RGX_CR_MTS_BGCTX_THREAD1_DM_ASSOC_MASKFULL);
    return 0;
}

static s_time_t gx6xxx_disable_threads(struct vcoproc_instance *vcoproc)
{
    struct coproc_device *coproc = vcoproc->coproc;
    int ret;

    /* disable thread 0 */
    ret = gx6xxx_write_via_slave_port32(coproc,
                                        META_CR_T0ENABLE_OFFSET,
                                        ~META_CR_TXENABLE_ENABLE_BIT);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    /* disable thread 1 */
    ret = gx6xxx_write_via_slave_port32(coproc,
                                        META_CR_T1ENABLE_OFFSET,
                                        ~META_CR_TXENABLE_ENABLE_BIT);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;
    /* clear down any irq raised by META (done after disabling the FW
     * threads to avoid a race condition).
     */
    gx6xxx_write32(coproc, RGX_CR_META_SP_MSLVIRQSTATUS, 0x0);
    return 0;
}

static s_time_t gx6xxx_wait_all_idle(struct vcoproc_instance *vcoproc)
{
    struct coproc_device *coproc = vcoproc->coproc;
    uint32_t val;
    int ret;

    /* wait for the slave port to finish all the transactions */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_META_SP_MSLVCTRL1,
                            RGX_CR_META_SP_MSLVCTRL1_READY_EN | RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN,
                            RGX_CR_META_SP_MSLVCTRL1_READY_EN | RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    /* extra idle checks */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_BIF_STATUS_MMU,
                            0, RGX_CR_BIF_STATUS_MMU_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_BIFPM_STATUS_MMU,
                            0, RGX_CR_BIFPM_STATUS_MMU_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_BIFPM_READS_EXT_STATUS,
                            0, RGX_CR_BIFPM_READS_EXT_STATUS_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg64(coproc, RGX_CR_SLC_STATUS1,
                            0, RGX_CR_SLC_STATUS1_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_SLC_IDLE,
                            RGX_CR_SLC_IDLE_MASKFULL,
                            RGX_CR_SLC_IDLE_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_SIDEKICK_IDLE,
                            RGX_CR_SIDEKICK_IDLE_MASKFULL^(RGX_CR_SIDEKICK_IDLE_GARTEN_EN|RGX_CR_SIDEKICK_IDLE_SOCIF_EN|RGX_CR_SIDEKICK_IDLE_HOSTIF_EN),
                            RGX_CR_SIDEKICK_IDLE_MASKFULL^(RGX_CR_SIDEKICK_IDLE_GARTEN_EN|RGX_CR_SIDEKICK_IDLE_SOCIF_EN|RGX_CR_SIDEKICK_IDLE_HOSTIF_EN));
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret =  gx6xxx_read_via_slave_port32(coproc, META_CR_TxVECINT_BHALT, &val);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    if ( (val & 0xFFFFFFFFU) == 0x0 )
    {
        /* Wait for Sidekick/Jones to signal IDLE including
         * the Garten Wrapper if there is no debugger attached
         * (TxVECINT_BHALT = 0x0) */
        ret = gx6xxx_poll_reg32(coproc, RGX_CR_SIDEKICK_IDLE,
                                RGX_CR_SIDEKICK_IDLE_GARTEN_EN,
                                RGX_CR_SIDEKICK_IDLE_GARTEN_EN);
        if ( unlikely(ret < 0) )
            return GX6XXX_WAIT_TIME_US;
    }
    return 0;
}

static s_time_t gx6xxx_wait_fw_stopped(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    int ret;

    ret = gx6xxx_wait_fw_started(vcoproc, vinfo, IMG_FALSE);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;
    return 0;
}

struct gx6xxx_ctx_switch_state gx6xxx_ctx_gpu_stop_states[] =
{
    /* FORCE IDLE */
    {
        .handler = gx6xxx_force_idle,
        .run_condition = gx6xxx_run_if_not_idle_or_off,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_force_idle",
#endif
    },
    {
        .handler = gx6xxx_wait_kccb,
        .run_condition = gx6xxx_run_if_not_idle_or_off,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_force_idle gx6xxx_wait_kccb",
#endif
    },
    {
        .handler = gx6xxx_wait_psync,
        .run_condition = gx6xxx_run_if_not_idle_or_off,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_force_idle gx6xxx_wait_psync",
#endif
    },
    {
        .handler = gx6xxx_force_idle_check,
        .run_condition = gx6xxx_run_if_not_idle_or_off,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_force_idle gx6xxx_force_idle_check",
#endif
    },
    /* REQUEST POWER OFF */
    {
        .handler = gx6xxx_request_power_off,
        .run_condition = gx6xxx_run_if_not_off,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_request_power_off",
#endif
    },
    {
        .handler = gx6xxx_wait_kccb,
        .run_condition = gx6xxx_run_if_not_off,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_request_power_off gx6xxx_wait_kccb",
#endif
    },
    {
        .handler = gx6xxx_wait_psync,
        .run_condition = gx6xxx_run_if_not_off,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_request_power_off gx6xxx_wait_psync",
#endif
    },
    /* WAIT FOR LAST CHANCE INTERRUPTS */
    {
        .handler = gx6xxx_wait_for_interrupts,
        .run_condition = gx6xxx_run_always,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_wait_for_interrupts",
#endif
    },
    /* FIXME: SAVE REGISTERS NOW */
    {
        .handler = gx6xxx_save_reg_ctx,
        .run_condition = gx6xxx_run_always,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_save_reg_ctx",
#endif
    },
    /* WAIT FOR SLC AND SIDEKICK */
    {
        .handler = gx6xxx_wait_for_slc_idle,
        .run_condition = gx6xxx_run_always,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_wait_for_slc_idle",
#endif
    },
    /* DE-ASSOCIATE ALL THREADS */
    {
        .handler = gx6xxx_deassoc_threads,
        .run_condition = gx6xxx_run_always,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_deassoc_threads",
#endif
    },
    /* DISABLE ALL THREADS */
    {
        .handler = gx6xxx_disable_threads,
        .run_condition = gx6xxx_run_always,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_disable_threads",
#endif
    },
    /* WAIT FOR ALL IDLE */
    {
        .handler = gx6xxx_wait_all_idle,
        .run_condition = gx6xxx_run_always,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_wait_all_idle",
#endif
    },
    /* WAIT FOR FW STOPPED */
    {
        .handler = gx6xxx_wait_fw_stopped,
        .run_condition = gx6xxx_run_always,
#ifdef GX6XXX_DEBUG
        .name = "gx6xxx_wait_fw_stopped",
#endif
    },
    {
        NULL
    }
};

#ifdef GX6XXX_DEBUG
static const char *power_state_to_str(RGXFWIF_POW_STATE state)
{
    switch (state)
    {
    case RGXFWIF_POW_OFF:
        return "RGXFWIF_POW_OFF";
    case RGXFWIF_POW_ON:
        return "RGXFWIF_POW_ON";
    case RGXFWIF_POW_FORCED_IDLE:
        return "RGXFWIF_POW_FORCED_IDLE";
    case RGXFWIF_POW_IDLE:
        return "RGXFWIF_POW_IDLE";
    default:
        break;
    }
    return "Unknown";
}
#endif

#define RGX_CR_SOFT_RESET_ALL   (RGX_CR_SOFT_RESET_MASKFULL)

int gx6xxx_ctx_gpu_start(struct vcoproc_instance *vcoproc,
                         struct vgx6xxx_info *vinfo)
{
    struct coproc_device *coproc = vcoproc->coproc;
    int ret;

    gx6xxx_restore_reg_ctx(vcoproc, vinfo);

    /* perform soft-reset */
    gx6xxx_write64(coproc, RGX_CR_SOFT_RESET, RGX_CR_SOFT_RESET_ALL);
    gx6xxx_write64(coproc, RGX_CR_SOFT_RESET,
                   RGX_CR_SOFT_RESET_ALL ^ RGX_CR_SOFT_RESET_RASCALDUSTS_EN);
    (void)gx6xxx_read64(coproc, RGX_CR_SOFT_RESET);

    /* start everything, but META */
    gx6xxx_write64(coproc, RGX_CR_SOFT_RESET, RGX_CR_SOFT_RESET_GARTEN_EN);

    gx6xxx_write32(coproc, RGX_CR_SLC_CTRL_MISC,
                   vinfo->reg_val_cr_slc_ctrl_misc.as.lo);
    gx6xxx_write32(coproc, RGX_CR_META_BOOT,
                   vinfo->reg_val_cr_meta_boot.as.lo);
    gx6xxx_write64(coproc, RGX_CR_MTS_GARTEN_WRAPPER_CONFIG,
                   vinfo->reg_val_cr_mts_garten_wrapper_config.val);
    gx6xxx_write64(coproc, RGX_CR_AXI_ACE_LITE_CONFIGURATION,
                   vinfo->reg_val_cr_axi_ace_lite_configuration.val);
    gx6xxx_write64(coproc, RGX_CR_BIF_CAT_BASE0,
                   vinfo->reg_val_cr_bif_cat_base0.val);

    /* wait for at least 16 cycles */
    udelay(32);

    gx6xxx_write64(coproc, RGX_CR_SOFT_RESET, 0x0);
    (void)gx6xxx_read64(coproc, RGX_CR_SOFT_RESET);

    /* wait for at least 16 cycles */
    udelay(32);

    /* FIXME: if slave is booting then it needs a kick to start */

    /* finally check that FW reports it's started */
    ret = gx6xxx_wait_fw_started(vcoproc, vinfo, IMG_TRUE);
    if ( ret < 0 )
    {
        dev_err(coproc->dev, "Firmware has not yet started\n");
        /* TODO: context switch to cannot handle wait_time as context
         * switch from does. this needs to be addressed
         */
#if 0
        return ret;
#endif
    }
    return 0;
}

/* try stopping the GPU: 0 on success, <0 if still busy */
int gx6xxx_ctx_gpu_stop(struct vcoproc_instance *vcoproc,
                        struct vgx6xxx_info *vinfo)
{
    struct coproc_device *coproc = vcoproc->coproc;
    struct gx6xxx_info *info = (struct gx6xxx_info *)coproc->priv;
    s_time_t wait_time;

    /* XXX: we CANNOT receive interrupts at this time - scheduler has
     * disabled the interrupts
     */
#ifdef GX6XXX_DEBUG
    dev_dbg(vcoproc->coproc->dev, "%s sPowerState is %s\n",
            __FUNCTION__, power_state_to_str(vinfo->fw_trace_buf->ePowState));
#endif
    dev_dbg(vcoproc->coproc->dev, "%s FW reports %d vs Xen %d IRQs\n",
           __FUNCTION__, vinfo->fw_trace_buf->aui32InterruptCount[0],
           atomic_read(&vinfo->irq_count));
    while ( info->state_curr->handler )
    {
#ifdef GX6XXX_DEBUG
        dev_dbg(vcoproc->coproc->dev, "%s state %s\n", __FUNCTION__,
                info->state_curr->name);
#endif
        /* if there is an interrupt pending return minimally possible
         * time, so scheduler unlocks interrupts and we have a chance to
         * handle it
         */
        if ( gx6xxx_is_irq_pending(info) )
            return 1;

        if ( likely(info->state_curr->run_condition(vcoproc)) )
        {
            wait_time = info->state_curr->handler(vcoproc);
            if ( wait_time > 0 )
            {
#ifdef GX6XXX_DEBUG
                info->state_curr->num_retries++;
#endif
                return wait_time;
            }
            if ( wait_time < 0 )
            {
                dev_dbg(vcoproc->coproc->dev, "%s wait_time %ld\n", __FUNCTION__,
                        wait_time);
                /* step failed */
                if ( wait_time == -EAGAIN )
                {

                }
                break;
            }
        }
        /* ready for the next step */
        info->state_curr++;
    }
    if ( unlikely(!info->state_curr) )
        dev_dbg(vcoproc->coproc->dev, "%s GPU stopped =============================================\n", __FUNCTION__);
    return 0;
}

