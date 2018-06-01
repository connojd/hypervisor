
#ifndef BF_BASE_H
#define BF_BASE_H

#include "efi.h"
#include "efilib.h"

typedef struct {
    uint64_t version;
    uint64_t startup_data;
} startup_data_t;

void _set_ne()
{
    __asm volatile("movq %%cr0, %%rax\n \
                    orq $(1<<5), %%rax\n \
                    movq %%rax, %%cr0" : : : "rax");
}

int64_t platform_start_core(void);

#endif
