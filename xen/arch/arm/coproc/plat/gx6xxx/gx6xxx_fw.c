#include <xen/delay.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <xen/pfn.h>
#include <xen/vmap.h>

#include "gx6xxx_coproc.h"
#include "gx6xxx_fw.h"
#include "gx6xxx_hexdump.h"

/* this is the time out to wait for the firmware to consume
 * a command sent from the kernel
 */
#define GX6XXX_WAIT_FW_TO_US    500

#define RGXFW_SEGMMU_DATA_CACHE_MASK    (RGXFW_SEGMMU_DATA_BASE_ADDRESS     | \
                                         RGXFW_SEGMMU_DATA_META_CACHED      | \
                                         RGXFW_SEGMMU_DATA_META_UNCACHED    | \
                                         RGXFW_SEGMMU_DATA_VIVT_SLC_CACHED  | \
                                         RGXFW_SEGMMU_DATA_VIVT_SLC_UNCACHED)

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

static mfn_t gx6xxx_fw_mmu_devaddr_to_mfn(struct vcoproc_instance *vcoproc,
                                          struct vgx6xxx_info *vinfo,
                                          uint64_t dev_vaddr)
{
    int idx, order;
    mfn_t mfn;
    uint64_t *pg64;
    uint64_t ipa;

    dev_dbg(vcoproc->coproc->dev,
            "%s dev_vaddr %lx\n", __FUNCTION__, dev_vaddr);
    /* get index in the page directory */
    idx = vaddr_to_pde_idx(dev_vaddr);
    BUG_ON(idx >= RGX_MMUCTRL_ENTRIES_PD_VALUE);
    pg64 = (uint64_t *)map_domain_page(vinfo->mfn_pd);
    if ( unlikely(!pg64) )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to map page directory MFN %lx\n", vinfo->mfn_pd);
        return INVALID_MFN;
    }
    clean_and_invalidate_dcache_va_range(pg64, PAGE_SIZE);
    dev_dbg(vcoproc->coproc->dev,
            "page directory MFN %lx\n", vinfo->mfn_pd);
#if 0
    gx6xxx_dump((uint32_t *)pg64, PAGE_SIZE);
#endif
    /* read PT base address */
    ipa = get_pt_addr_and_order(pg64[idx], &order);
    unmap_domain_page(pg64);

    if ( unlikely(!ipa) )
    {
        dev_err(vcoproc->coproc->dev, "no valid IPA for page table\n");
        return INVALID_MFN;
    }
    /* FIXME: we only expect 4K pages for now */
    BUG_ON(order != 0);
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    dev_dbg(vcoproc->coproc->dev, "page table IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        dev_err(vcoproc->coproc->dev, "failed to lookup page table\n");
        return INVALID_MFN;
    }
    /* get index in the page table */
    idx = vaddr_to_pte_idx(dev_vaddr);
    BUG_ON(idx >= RGX_MMUCTRL_ENTRIES_PT_VALUE);
    pg64 = (uint64_t *)map_domain_page(mfn);
    if ( unlikely(!pg64) )
    {
        dev_err(vcoproc->coproc->dev, "failed to map page table MFN %lx\n", mfn);
        return INVALID_MFN;
    }
    clean_and_invalidate_dcache_va_range(pg64, PAGE_SIZE);
#if 0
    gx6xxx_dump((uint32_t *)pg64, PAGE_SIZE);
#endif
    /* read PT base address */
    ipa = get_pte_addr(pg64[idx]);
    unmap_domain_page(pg64);

    if ( unlikely(!ipa) )
    {
        dev_err(vcoproc->coproc->dev,
                "no valid IPA for page table entry for vaddr %lx\n", dev_vaddr);
        return INVALID_MFN;
    }
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    dev_dbg(vcoproc->coproc->dev, "page table entry IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to lookup page table entry for %lx\n", dev_vaddr);
        return INVALID_MFN;
    }
    return mfn;
}

static inline uint64_t gx6xxx_fw_mmu_meta_to_dev_vaddr(uint32_t meta_addr)
{
    return (meta_addr & ~RGXFW_SEGMMU_DATA_CACHE_MASK) +
            RGX_FIRMWARE_HEAP_BASE;
}

/* N.B. Kernel driver allocates structures shared with the FW from a
 * contigous heap. Thus, there is no guarantee that what we map is
 * PAGE_SIZE aligned. What is more, even 8-byte structure can be
 * spread over 2 consecutive pages, e.g. 4 bytes at the end of a page
 * and 4 bytes at the very beginning
 */
static inline void *gx6xxx_fw_mmu_map(struct vcoproc_instance *vcoproc,
                                      struct vgx6xxx_info *vinfo,
                                      uint64_t fw_dev_addr, size_t size)
{
    /* FIXME: up to 3 pages can be mapped */
    mfn_t mfn[3];
    unsigned char *vaddr;
    size_t map_sz, left_sz;
    uint32_t offset;
    uint64_t cur_dev_addr;
    int i;

    dev_dbg(vcoproc->coproc->dev, "mapping dev address %lx, size %zu\n",
            fw_dev_addr, size);
    /* TODO: we only map buffers less than 2 pages for now */
    BUG_ON(size > PAGE_SIZE * 2);

    cur_dev_addr = fw_dev_addr & PAGE_MASK;
    offset = fw_dev_addr & (PAGE_SIZE - 1);
    map_sz = offset + size <= PAGE_SIZE ? size : PAGE_SIZE - offset;
    left_sz = size;
    for (i = 0; i < ARRAY_SIZE(mfn); i++)
    {
        /* this mapping fits into a single page */
        mfn[i] = gx6xxx_fw_mmu_devaddr_to_mfn(vcoproc, vinfo, cur_dev_addr);
        if ( unlikely(mfn[i] == INVALID_MFN) )
        {
            dev_err(vcoproc->coproc->dev,
                    "failed to find MFN for dev address %lx\n",
                    cur_dev_addr);
            return ERR_PTR(-EINVAL);
        }
        left_sz -= map_sz;
        if ( !left_sz )
            break;
        cur_dev_addr += PAGE_SIZE;
        map_sz = left_sz <= PAGE_SIZE ? left_sz : PAGE_SIZE;
    }
    vaddr = __vmap(mfn, PFN_UP(offset + size), 1, 1,
                   PAGE_HYPERVISOR_NOCACHE, VMAP_DEFAULT);
    if ( unlikely(!vaddr) )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to map for dev address %lx\n", fw_dev_addr);
        return ERR_PTR(-EINVAL);
    }
    return vaddr + offset;
}

static inline void gx6xxx_fw_mmu_unmap(void *vaddr)
{
    if ( unlikely(!IS_ERR_OR_NULL(vaddr)) )
        return;
    vunmap((void *)((uint64_t)vaddr & PAGE_MASK));
}

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

/*
 * Find MFNs for page catalog and page directory,
 * so we don't need to lookup those during translations
 */
static int gx6xxx_fw_mmu_init(struct vcoproc_instance *vcoproc,
                              struct vgx6xxx_info *vinfo)
{
    uint64_t ipa;
    uint32_t *pgc;
    int idx;
    mfn_t mfn;

    vinfo->mfn_pc = INVALID_MFN;
    vinfo->mfn_pd = INVALID_MFN;

    /* FIXME: reg_val_cr_bif_cat_base0 has a physical address of the page
     * catalog (PC) which is one page */
    /* FIXME: only one page must be in PC which is page directory (PD) */
    ipa = vinfo->reg_val_cr_bif_cat_base0.val;
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    dev_dbg(vcoproc->coproc->dev, "page catalog IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        dev_err(vcoproc->coproc->dev, "failed to lookup page catalog\n");
        return -EINVAL;
    }
    /* get index in the page catalog */
    idx = vaddr_to_pce_idx(RGX_FIRMWARE_HEAP_BASE);
    BUG_ON(idx >= RGX_MMUCTRL_ENTRIES_PC_VALUE);
    pgc = (uint32_t *)map_domain_page(mfn);
    if ( unlikely(!pgc) )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to map page catalog, MFN %lx\n", mfn);
        return -EINVAL;
    }
    clean_and_invalidate_dcache_va_range(pgc, PAGE_SIZE);
#if 0
    gx6xxx_dump(pgc, PAGE_SIZE);
#endif
    /* read PD base address */
    ipa = get_pd_addr(pgc[idx]);
    unmap_domain_page(pgc);
    vinfo->mfn_pc = mfn;

    if ( unlikely(!ipa) )
    {
        dev_err(vcoproc->coproc->dev, "no valid IPA for page directory\n");
        return -EINVAL;
    }
    /* we have page catalog entry, so we can read page directory */
    mfn = p2m_lookup(vcoproc->domain, _gfn(paddr_to_pfn(ipa)), NULL);
    dev_dbg(vcoproc->coproc->dev, "page directory IPA %lx MFN %lx\n", ipa, mfn);
    if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
    {
        dev_err(vcoproc->coproc->dev, "failed to lookup page directory\n");
        return -EINVAL;
    }
    vinfo->mfn_pd = mfn;
    return 0;
}

static int gx6xxx_fw_map_all(struct vcoproc_instance *vcoproc,
                             struct vgx6xxx_info *vinfo,
                             uint64_t fw_init_dev_addr)
{
    RGXFWIF_INIT *fw_init;
    uint64_t fw_dev_addr;
    size_t size;
    const char *err_msg;
    int ret = -EINVAL;

    fw_init = gx6xxx_fw_mmu_map(vcoproc, vinfo, fw_init_dev_addr, sizeof(*fw_init));
    if ( unlikely(!fw_init) )
    {
        dev_err(vcoproc->coproc->dev, "cannot map RGXFWIF_INIT\n");
        return -EINVAL;
    }

    /* Kernel CCBCtl */
    fw_dev_addr = gx6xxx_fw_mmu_meta_to_dev_vaddr(fw_init->psKernelCCBCtl.ui32Addr);
    size = sizeof(*vinfo->fw_kernel_ccb_ctl);
    vinfo->fw_kernel_ccb_ctl = gx6xxx_fw_mmu_map(vcoproc, vinfo,
                                                 fw_dev_addr, size);
    if ( IS_ERR_OR_NULL(vinfo->fw_kernel_ccb_ctl) )
    {
        err_msg = "Kernel CCBCtl";
        ret = PTR_ERR(vinfo->fw_kernel_ccb_ctl);
        goto fail;
    }
    /* Kernel CCB */
    fw_dev_addr = gx6xxx_fw_mmu_meta_to_dev_vaddr(fw_init->psKernelCCB.ui32Addr);
    size = (vinfo->fw_kernel_ccb_ctl->ui32WrapMask + 1) * sizeof(RGXFWIF_KCCB_CMD);
    vinfo->fw_kernel_ccb = gx6xxx_fw_mmu_map(vcoproc, vinfo, fw_dev_addr, size);
    if ( IS_ERR_OR_NULL(vinfo->fw_kernel_ccb) )
    {
        err_msg = "Kernel CCB";
        ret = PTR_ERR(vinfo->fw_kernel_ccb);
        goto fail;
    }

    /* Firmware CCBCtl */
    fw_dev_addr = gx6xxx_fw_mmu_meta_to_dev_vaddr(fw_init->psFirmwareCCBCtl.ui32Addr);
    size = sizeof(*vinfo->fw_firmware_ccb_ctl);
    vinfo->fw_firmware_ccb_ctl = gx6xxx_fw_mmu_map(vcoproc, vinfo,
                                                   fw_dev_addr, size);
    if ( IS_ERR_OR_NULL(vinfo->fw_firmware_ccb_ctl) )
    {
        err_msg = "Firmware CCBCtl";
        ret = PTR_ERR(vinfo->fw_firmware_ccb_ctl);
        goto fail;
    }
    /* Firmware CCB */
    fw_dev_addr = gx6xxx_fw_mmu_meta_to_dev_vaddr(fw_init->psFirmwareCCB.ui32Addr);
    size = (vinfo->fw_firmware_ccb_ctl->ui32WrapMask + 1) * sizeof(RGXFWIF_FWCCB_CMD);
    vinfo->fw_firmware_ccb = gx6xxx_fw_mmu_map(vcoproc, vinfo,
                                               fw_dev_addr, size);
    if ( IS_ERR_OR_NULL(vinfo->fw_firmware_ccb) )
    {
        err_msg = "Firmware CCB";
        ret = PTR_ERR(vinfo->fw_firmware_ccb);
        goto fail;
    }

    /* Trace buffer */
    fw_dev_addr = gx6xxx_fw_mmu_meta_to_dev_vaddr(fw_init->sTraceBufCtl.ui32Addr);
    size = sizeof(*vinfo->fw_trace_buf);
    vinfo->fw_trace_buf = gx6xxx_fw_mmu_map(vcoproc, vinfo, fw_dev_addr, size);
    if ( IS_ERR_OR_NULL(vinfo->fw_trace_buf) )
    {
        err_msg = "FW trace buffer";
        ret = PTR_ERR(vinfo->fw_trace_buf);
        goto fail;
    }

    /* Power sync object */
    fw_dev_addr = gx6xxx_fw_mmu_meta_to_dev_vaddr(fw_init->sPowerSync.ui32Addr);
    size = sizeof(*vinfo->fw_power_sync);
    vinfo->fw_power_sync = gx6xxx_fw_mmu_map(vcoproc, vinfo, fw_dev_addr, size);
    if ( IS_ERR_OR_NULL((IMG_UINT32 *)vinfo->fw_power_sync) )
    {
        err_msg = "PowerSync object";
        ret = PTR_ERR((IMG_UINT32 *)vinfo->fw_power_sync);
        goto fail;
    }
    gx6xxx_fw_mmu_unmap(fw_init);
    return 0;

fail:
    dev_err(vcoproc->coproc->dev, "failed to map %s\n", err_msg);
    return ret;
}

int gx6xxx_fw_init(struct vcoproc_instance *vcoproc,
                   struct vgx6xxx_info *vinfo)
{
    uint64_t fw_init_dev_addr;
    uint64_t *fw_cfg, *fw_cfg_last, *fw_heap_base;
    int ret;

    /* RGX_CR_BIF_CAT_BASE0 must be set by this time */
    ret = gx6xxx_fw_mmu_init(vcoproc, vinfo);
    /* TODO: need to handle */
    BUG_ON(ret < 0);

    fw_heap_base = gx6xxx_fw_mmu_map(vcoproc, vinfo,
                                     RGX_FIRMWARE_HEAP_BASE, PAGE_SIZE);
    if ( unlikely(!fw_heap_base) )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to map at RGX_FIRMWARE_HEAP_BASE\n");
        return -EFAULT;
    }
    /* skip RGXFW_BOOTLDR_CONF_OFFSET uint32_t values to get
     * to the configuration
     */
    fw_cfg = fw_heap_base;
    /* must not read after this pointer */
    fw_cfg_last = fw_heap_base + PAGE_SIZE/sizeof(*fw_heap_base);
    fw_cfg += RGXFW_BOOTLDR_CONF_OFFSET / 2;
    /* now skip all non-zero values - those are pairs of register:value
     * used by the firmware during initialization
     */
    while ( (fw_cfg < fw_cfg_last) && *fw_cfg++ )
        continue;
    if ( fw_cfg == fw_cfg_last )
    {
        dev_err(vcoproc->coproc->dev,
                "failed to find RGXFWIF_INIT structure\n");
        ret = -EINVAL;
        goto fail;
    }
    /* right after the terminator (64-bits of zeros) there is a pointer
     * to the RGXFWIF_INIT structure
     */
    /* convert the address from META address space into what MMU sees */
    fw_init_dev_addr = gx6xxx_fw_mmu_meta_to_dev_vaddr(*((uint32_t *)fw_cfg));
    dev_dbg(vcoproc->coproc->dev,
            "found RGXFWIF_INIT structure address: %lx\n", fw_init_dev_addr);
    ret = gx6xxx_fw_map_all(vcoproc, vinfo, fw_init_dev_addr);
    if ( unlikely(ret < 0) )
        return ret;
    gx6xxx_fw_mmu_unmap(fw_heap_base);
    return 0;

fail:
    gx6xxx_fw_mmu_unmap(fw_heap_base);
    return ret;
}

void gx6xxx_fw_deinit(struct vcoproc_instance *vcoproc,
                      struct vgx6xxx_info *vinfo)
{
    gx6xxx_fw_mmu_unmap(vinfo->fw_trace_buf);
    gx6xxx_fw_mmu_unmap(vinfo->fw_kernel_ccb);
    gx6xxx_fw_mmu_unmap(vinfo->fw_kernel_ccb_ctl);
    gx6xxx_fw_mmu_unmap(vinfo->fw_firmware_ccb);
    gx6xxx_fw_mmu_unmap(vinfo->fw_firmware_ccb_ctl);
    gx6xxx_fw_mmu_unmap((IMG_UINT32 *)vinfo->fw_power_sync);
}

/* get new write offset for Kernel messages to FW */
void gx6xxx_dump_kernel_ccb(struct vcoproc_instance *vcoproc,
                            struct vgx6xxx_info *vinfo)
{
    uint32_t wrap_mask, read_ofs, write_ofs;
    const char *cmd_name;

    /* we are stealing the read offset which is modified by the FW */
    read_ofs = vinfo->fw_kernel_ccb_ctl->ui32ReadOffset;
    write_ofs = vinfo->fw_kernel_ccb_ctl->ui32WriteOffset;
    wrap_mask = vinfo->fw_kernel_ccb_ctl->ui32WrapMask;
    while ( read_ofs != write_ofs )
    {
        RGXFWIF_KCCB_CMD *cmd;

        if ( read_ofs > wrap_mask || write_ofs > wrap_mask )
        {
            dev_err(vcoproc->coproc->dev,"stalled messages???\n");
            return;
        }

        cmd = ((RGXFWIF_KCCB_CMD *)vinfo->fw_kernel_ccb) + read_ofs;

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
            printk("RGXFWIF_KCCB_CMD_SYNC %x uiUpdateVal %d\n",
                   cmd->uCmdData.sSyncData.sSyncObjDevVAddr.ui32Addr,
                   cmd->uCmdData.sSyncData.uiUpdateVal);
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
            printk("Unknown KCCB command %d at ui32ReadOffset %d\n",
                   cmd->eCmdType, read_ofs);
            BUG();
        }
        printk("KCCB cmd: %s (%d)\n", cmd_name, cmd->eCmdType);
        read_ofs = (read_ofs + 1) & wrap_mask;
    }
}

static int gx6xxx_get_kernel_ccb_slot(struct vgx6xxx_info *vinfo,
                                      uint32_t *write_offset)
{
    uint32_t curr_offset, new_offset;
    int retry = GX6XXX_WAIT_FW_TO_US;

    curr_offset = vinfo->fw_kernel_ccb_ctl->ui32WriteOffset;
    new_offset = (curr_offset + 1) & vinfo->fw_kernel_ccb_ctl->ui32WrapMask;
    do
    {
        if ( likely(new_offset != vinfo->fw_kernel_ccb_ctl->ui32ReadOffset) )
        {
            *write_offset = new_offset;
            return 0;
        }
        udelay(1);
    } while ( retry-- );
    return -ETIMEDOUT;
}

int gx6xxx_send_kernel_ccb_cmd(struct vcoproc_instance *vcoproc,
                               struct vgx6xxx_info *vinfo,
                               RGXFWIF_KCCB_CMD *cmd, uint32_t cmd_sz)
{
    uint32_t curr_offset, new_offset = 0, ret;

    curr_offset = vinfo->fw_kernel_ccb_ctl->ui32WriteOffset;
    ret = gx6xxx_get_kernel_ccb_slot(vinfo, &new_offset);
    if ( unlikely(ret < 0) )
        return ret;
    memcpy(&vinfo->fw_firmware_ccb[curr_offset * cmd_sz], cmd, cmd_sz);
    smp_wmb();
    vinfo->fw_kernel_ccb_ctl->ui32WriteOffset = new_offset;
    gx6xxx_write32(vcoproc->coproc, RGX_CR_MTS_SCHEDULE,
                   RGX_CR_MTS_SCHEDULE_TASK_COUNTED);
    printk("%s ui32WriteOffset %d\n", __FUNCTION__, new_offset);
    return 0;
}
