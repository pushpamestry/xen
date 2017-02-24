#include "gx6xxx_coproc.h"
#include "gx6xxx_fw.h"
#include "gx6xxx_mmu.h"
#include "rgx_meta.h"
#include "rgxmmudefs_km.h"

static int gx6xxx_fw_parse_init(struct vcoproc_instance *vcoproc,
                                struct vgx6xxx_info *vinfo)
{
    int ret = -EFAULT;
    RGXFWIF_INIT *fw_init = gx6xxx_mmu_map(vinfo->mfn_rgx_fwif_init);

    vinfo->mfn_kernel_ccb = INVALID_MFN;
    vinfo->mfn_kernel_ccb_ctl = INVALID_MFN;
    vinfo->mfn_firmware_ccb = INVALID_MFN;
    vinfo->mfn_firmware_ccb_ctl = INVALID_MFN;

    if ( unlikely(!fw_init) )
    {
        printk("Cannot map RGXFWIF_INIT\n");
        return -EFAULT;
    }
    printk("RGXFWIF_INIT = %lu\n", sizeof(RGXFWIF_INIT));
    printk("%s dumping RGXFWIF_INIT\n", __FUNCTION__);
    printk("psKernelCCB %lx\n", gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psKernelCCB.ui32Addr));
    printk("psKernelCCBCtl %lx\n", gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psKernelCCBCtl.ui32Addr));
    printk("psFirmwareCCB %lx\n", gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psFirmwareCCB.ui32Addr));
    printk("psFirmwareCCBCtl %lx\n", gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psFirmwareCCBCtl.ui32Addr));

    /* kernel */
    vinfo->mfn_kernel_ccb = gx6xxx_mmu_devaddr_to_mfn(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psKernelCCB.ui32Addr));
    if ( unlikely(vinfo->mfn_kernel_ccb == INVALID_MFN) )
        goto out;
    printk("psKernelCCB MFN %lx\n", vinfo->mfn_kernel_ccb);

    vinfo->mfn_kernel_ccb_ctl = gx6xxx_mmu_devaddr_to_mfn(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psKernelCCBCtl.ui32Addr));
    if ( unlikely(vinfo->mfn_kernel_ccb_ctl == INVALID_MFN) )
        goto out;
    printk("psKernelCCBCtl MFN %lx\n", vinfo->mfn_kernel_ccb);

    /* firmware */
    vinfo->mfn_firmware_ccb = gx6xxx_mmu_devaddr_to_mfn(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psFirmwareCCB.ui32Addr));
    if ( unlikely(vinfo->mfn_firmware_ccb == INVALID_MFN) )
        goto out;
    printk("psFirmwareCCB MFN %lx\n", vinfo->mfn_firmware_ccb);

    vinfo->mfn_firmware_ccb_ctl = gx6xxx_mmu_devaddr_to_mfn(vcoproc, vinfo,
                    gx6xxx_mmu_meta_to_dev_vaddr(fw_init->psFirmwareCCBCtl.ui32Addr));
    if ( unlikely(vinfo->mfn_firmware_ccb_ctl == INVALID_MFN) )
        goto out;
    printk("psFirmwareCCBCtl MFN %lx\n", vinfo->mfn_firmware_ccb);

    ret = 0;
out:
    gx6xxx_mmu_unmap(fw_init);
    return ret;
}

int gx6xxx_fw_init(struct vcoproc_instance *vcoproc,
                   struct vgx6xxx_info *vinfo, mfn_t mfn_heap_base)
{
    uint64_t fw_init_dev_addr;
    uint64_t *fw_cfg, *ptr = gx6xxx_mmu_map(mfn_heap_base);

    vinfo->mfn_rgx_fwif_init = INVALID_MFN;
    if ( unlikely(!ptr) )
        return -EFAULT;
    /* skip RGXFW_BOOTLDR_CONF_OFFSET uint32_t values to get
     * to the configuration
     */
    fw_cfg = ptr;
    fw_cfg += RGXFW_BOOTLDR_CONF_OFFSET / 2;
    /* now skip all non-zero values - those are pairs of register:value
     * used by the firmware during initialization
     */
    while (*fw_cfg++)
        continue;
    /* right after the terminator (64-bits of zeros) there is a pointer
     * to the RGXFWIF_INIT structure
     * TODO: check for wrong configuration - do not read after the page end
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
    return gx6xxx_fw_parse_init(vcoproc, vinfo);
}
