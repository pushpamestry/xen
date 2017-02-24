#include "gx6xxx_coproc.h"
#include "gx6xxx_fw.h"
#include "gx6xxx_mmu.h"
#include "rgx_meta.h"
#include "rgxmmudefs_km.h"

int gx6xxx_fw_init(struct vcoproc_instance *vcoproc,
                   struct vgx6xxx_info *vinfo, mfn_t mfn_heap_base)
{
    uint64_t fw_init_dev_addr;
    uint64_t *fw_cfg, *ptr = gx6xxx_mmu_map(mfn_heap_base);

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
    fw_init_dev_addr = *((uint32_t *)fw_cfg);
    /* convert the address from META address space into what MMU sees */
    fw_init_dev_addr -= RGXFW_SEGMMU_DATA_BASE_ADDRESS;
    fw_init_dev_addr -= RGXFW_SEGMMU_DATA_VIVT_SLC_UNCACHED;
    fw_init_dev_addr += RGX_FIRMWARE_HEAP_BASE;
    /* we are all set */
    gx6xxx_mmu_unmap(ptr);
    printk("Found RGXFWIF_INIT structure at %lx\n", fw_init_dev_addr);
    /* now get its MFN */
    return 0;
}
