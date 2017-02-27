#include "gx6xxx_coproc.h"
#include "gx6xxx_fw.h"
#include "gx6xxx_mmu.h"

static int gx6xxx_fw_parse_init(struct vcoproc_instance *vcoproc,
                                struct vgx6xxx_info *vinfo)
{
    int ret = -EFAULT;
    RGXFWIF_INIT *fw_init = gx6xxx_mmu_map(vinfo->mfn_rgx_fwif_init);

    vinfo->maddr_kernel_ccb = INVALID_MFN;
    vinfo->maddr_kernel_ccb_ctl = INVALID_MFN;
    vinfo->maddr_firmware_ccb = INVALID_MFN;
    vinfo->maddr_firmware_ccb_ctl = INVALID_MFN;
    vinfo->maddr_trace_buf_ctl = INVALID_MFN;

    if ( unlikely(!fw_init) )
    {
        printk("Cannot map RGXFWIF_INIT\n");
        return -EFAULT;
    }
    /* kernel */
    vinfo->maddr_kernel_ccb = gx6xxx_mmu_devaddr_to_maddr(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psKernelCCB.ui32Addr));
    if ( unlikely(vinfo->maddr_kernel_ccb == INVALID_MFN) )
        goto out;

    vinfo->maddr_kernel_ccb_ctl = gx6xxx_mmu_devaddr_to_maddr(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psKernelCCBCtl.ui32Addr));
    if ( unlikely(vinfo->maddr_kernel_ccb_ctl == INVALID_MFN) )
        goto out;

    /* firmware */
    vinfo->maddr_firmware_ccb = gx6xxx_mmu_devaddr_to_maddr(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psFirmwareCCB.ui32Addr));
    if ( unlikely(vinfo->maddr_firmware_ccb == INVALID_MFN) )
        goto out;

    vinfo->maddr_firmware_ccb_ctl = gx6xxx_mmu_devaddr_to_maddr(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psFirmwareCCBCtl.ui32Addr));
    if ( unlikely(vinfo->maddr_firmware_ccb_ctl == INVALID_MFN) )
        goto out;

    vinfo->maddr_trace_buf_ctl = gx6xxx_mmu_devaddr_to_maddr(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->sTraceBufCtl.ui32Addr));
    if ( unlikely(vinfo->maddr_trace_buf_ctl == INVALID_MFN) )
        goto out;

    ret = 0;
out:
    gx6xxx_mmu_unmap(fw_init);
    return ret;
}

static void *gx6xxx_fw_map_buf(paddr_t maddr)
{
    unsigned char *vaddr;

    if ( unlikely(!maddr) )
        return 0;
    /* FIXME: is it ok to map same page twice or more?
     * this can happen if CCBs are sharing the same page
     */
    vaddr = gx6xxx_mmu_map(paddr_to_pfn(maddr));
    if ( unlikely(!vaddr) )
        return ERR_PTR(-EFAULT);
    return vaddr + GX6XXX_MMU_PAGE_OFFSET(maddr);
}

static void gx6xxx_fw_unmap_buf(void *vaddr)
{
    if ( !IS_ERR_OR_NULL(vaddr) )
        gx6xxx_mmu_unmap((void *)((paddr_t)vaddr & PAGE_MASK));
}

int gx6xxx_fw_init(struct vcoproc_instance *vcoproc,
                   struct vgx6xxx_info *vinfo, mfn_t mfn_heap_base)
{
    const char *err_msg;
    int ret;
    uint64_t fw_init_dev_addr;
    uint64_t *fw_cfg, *fw_cfg_last, *ptr = gx6xxx_mmu_map(mfn_heap_base);

    vinfo->mfn_rgx_fwif_init = INVALID_MFN;
    if ( unlikely(!ptr) )
        return -EFAULT;
    /* skip RGXFW_BOOTLDR_CONF_OFFSET uint32_t values to get
     * to the configuration
     */
    fw_cfg = ptr;
    /* must not read after this pointer */
    fw_cfg_last = ptr + PAGE_SIZE/sizeof(*ptr);
    fw_cfg += RGXFW_BOOTLDR_CONF_OFFSET / 2;
    /* now skip all non-zero values - those are pairs of register:value
     * used by the firmware during initialization
     */
    while ( (fw_cfg < fw_cfg_last) && *fw_cfg++ )
        continue;
    if ( fw_cfg == fw_cfg_last )
    {
        dev_err(vcoproc->coproc->dev, "failed to find RGXFWIF_INIT structure\n");
        return -EINVAL;
    }
    /* right after the terminator (64-bits of zeros) there is a pointer
     * to the RGXFWIF_INIT structure
     */
    /* convert the address from META address space into what MMU sees */
    fw_init_dev_addr = gx6xxx_mmu_meta_to_dev_vaddr(*((uint32_t *)fw_cfg));
    gx6xxx_mmu_unmap(ptr);
    printk("Found RGXFWIF_INIT structure address: %lx\n", fw_init_dev_addr);
    /* now get its MFN */
    vinfo->mfn_rgx_fwif_init = gx6xxx_mmu_devaddr_to_mfn(vcoproc, vinfo,
                                                         fw_init_dev_addr);
    if ( unlikely(vinfo->mfn_rgx_fwif_init == INVALID_MFN) )
        return -EFAULT;
    ret = gx6xxx_fw_parse_init(vcoproc, vinfo);
    if ( unlikely(ret < 0) )
        return ret;
    vinfo->fw_trace_buf = gx6xxx_fw_map_buf(vinfo->maddr_trace_buf_ctl);
    if ( IS_ERR_OR_NULL(vinfo->fw_trace_buf) )
    {
        err_msg = "FW trace buffer";
        ret = PTR_ERR(vinfo->fw_trace_buf);
        goto fail;
    }
    vinfo->fw_kernel_ccb_ctl = gx6xxx_fw_map_buf(vinfo->maddr_kernel_ccb_ctl);
    if ( IS_ERR_OR_NULL(vinfo->fw_kernel_ccb_ctl) )
    {
        err_msg = "Kernel CCBCtl";
        ret = PTR_ERR(vinfo->fw_kernel_ccb_ctl);
        goto fail;
    }
    vinfo->fw_kernel_ccb = gx6xxx_fw_map_buf(vinfo->maddr_kernel_ccb);
    if ( IS_ERR_OR_NULL(vinfo->fw_kernel_ccb) )
    {
        err_msg = "Kernel CCB";
        ret = PTR_ERR(vinfo->fw_kernel_ccb);
        goto fail;
    }
    vinfo->fw_firmware_ccb_ctl = gx6xxx_fw_map_buf(vinfo->maddr_firmware_ccb_ctl);
    if ( IS_ERR_OR_NULL(vinfo->fw_firmware_ccb_ctl) )
    {
        err_msg = "Firmware CCBCtl";
        ret = PTR_ERR(vinfo->fw_firmware_ccb_ctl);
        goto fail;
    }
    vinfo->fw_firmware_ccb = gx6xxx_fw_map_buf(vinfo->maddr_firmware_ccb);
    if ( IS_ERR_OR_NULL(vinfo->fw_firmware_ccb) )
    {
        err_msg = "Firmware CCB";
        ret = PTR_ERR(vinfo->fw_firmware_ccb);
        goto fail;
    }
    return 0;

fail:
    dev_err(vcoproc->coproc->dev, "failed to map %s\n", err_msg);
    return ret;
}

void gx6xxx_fw_deinit(struct vcoproc_instance *vcoproc,
                      struct vgx6xxx_info *vinfo)
{
    gx6xxx_fw_unmap_buf(vinfo->fw_trace_buf);
    gx6xxx_fw_unmap_buf(vinfo->fw_kernel_ccb);
    gx6xxx_fw_unmap_buf(vinfo->fw_kernel_ccb_ctl);
    gx6xxx_fw_unmap_buf(vinfo->fw_firmware_ccb);
    gx6xxx_fw_unmap_buf(vinfo->fw_firmware_ccb_ctl);
}

/* get new write offset for Kernel messages to FW */
void gx6xxx_dump_kernel_ccb(struct vgx6xxx_info *vinfo)
{
    uint32_t wrap_mask, read_ofs, write_ofs;
    const char *cmd_name;

    /* FIXME: https://lists.gt.net/xen/devel/342092
     * only clean is needed?
     */
    clean_and_invalidate_dcache_va_range(vinfo->fw_kernel_ccb_ctl,
                                         sizeof(*vinfo->fw_kernel_ccb_ctl));

    /* we are stealing the read offset which is modified by the FW */
    read_ofs = vinfo->fw_kernel_ccb_ctl->ui32ReadOffset;
    write_ofs = vinfo->fw_kernel_ccb_ctl->ui32WriteOffset;
    wrap_mask = vinfo->fw_kernel_ccb_ctl->ui32WrapMask;
    while ( read_ofs != write_ofs )
    {
        RGXFWIF_KCCB_CMD *cmd;

        if ( read_ofs > wrap_mask || write_ofs > wrap_mask )
        {
            printk("Stalled messages???\n");
            return;
        }

        cmd = ((RGXFWIF_KCCB_CMD *)vinfo->fw_kernel_ccb) + read_ofs;
        /* FIXME: clean only? */
        clean_and_invalidate_dcache_va_range(cmd, sizeof(*cmd));

        switch(cmd->eCmdType)
        {
        case RGXFWIF_KCCB_CMD_KICK:
            cmd_name = "RGXFWIF_KCCB_CMD_KICK";
            break;
        case RGXFWIF_KCCB_CMD_MMUCACHE:
            cmd_name = "RGXFWIF_KCCB_CMD_MMUCACHE";
            break;
        case RGXFWIF_KCCB_CMD_SYNC:
            cmd_name = "RGXFWIF_KCCB_CMD_SYNC";
            break;
        case RGXFWIF_KCCB_CMD_SLCFLUSHINVAL:
            cmd_name = "RGXFWIF_KCCB_CMD_SLCFLUSHINVAL";
            break;
        case RGXFWIF_KCCB_CMD_CLEANUP:
            cmd_name = "RGXFWIF_KCCB_CMD_CLEANUP";
            break;
        case RGXFWIF_KCCB_CMD_HEALTH_CHECK:
            cmd_name = "RGXFWIF_KCCB_CMD_HEALTH_CHECK";
            break;
        default:
            printk("Unknown KCCB command: %d\n", cmd->eCmdType);
            BUG();
        }
        printk("KCCB cmd: %s (%d)\n", cmd_name, cmd->eCmdType);
        read_ofs = (read_ofs + 1) & wrap_mask;
    }
}
