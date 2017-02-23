#include "gx6xxx_coproc.h"

void gx6xxx_dump(uint32_t *vaddr, int size)
{
    int i, j;
    uint32_t *ptr = (uint32_t *)vaddr;

    for (i = 0; i < size / sizeof(uint32_t) / 4; i++)
    {
        for (j = 0; j < 4; j++)
            printk(" %08x", *ptr++);
        printk("\n");
    }
}
