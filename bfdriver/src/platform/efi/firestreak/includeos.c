/*
 * Bareflank Hypervisor
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "boot.h"
#include "bfelf_loader.h"
#include "common.h"
#include "efi.h"
#include "efilib.h"

extern char target_includeos_start[];
extern char target_includeos_end[];

void *platform_alloc_rw(uint64_t len);
void *platform_alloc_rwe(uint64_t len);

struct vmcall_regs {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
};

static inline void vmcall(struct vmcall_regs *regs)
{
    __asm volatile(
        "movq %0, %%rax\n\t"
        "movq %1, %%rbx\n\t"
        "movq %2, %%rcx\n\t"
        "movq %3, %%rdx\n\t"
        "vmcall\n\t"
        "movq %%rax, %4\n\t"
        "movq %%rbx, %5\n\t"
        "movq %%rcx, %6\n\t"
        "movq %%rdx, %7\n\t"
        : "=g"(regs->rax), "=g"(regs->rbx), "=g"(regs->rcx), "=g"(regs->rdx)
        : "m"(regs->rax), "m"(regs->rbx), "m"(regs->rcx), "m"(regs->rdx)
    );
}

#ifndef INCLUDEOS_MEM_SIZE
#define INCLUDEOS_MEM_SIZE (1ULL << 29U)
#endif

struct vm_context {
    uint8_t *mem;
    uint64_t mem_size;
    uint64_t img_base;
    uint64_t img_size;

};

// 1. Bareflank is running at this point
// 2. Need to setup includeos state:
//      -> EPT
//          * No need to worry about MTRRs since were using EFI
//            runtime memory
//          * EFI CR3 is identity mapped
//          * Need to present includeos with appropriate memory map
//      -> GDT
//      -> TSS
//      -> SRS
//      -> set guest_rip to target_includeos_start

boot_ret_t init_includeos()
{
//    uint64_t mem_size = INCLUDEOS_MEM_SIZE;
//    uint8_t *mem = platform_alloc_rwe(mem_size);
//    if (mem == NULL) {
//        Print(L"init_includeos: memory allocation failed\n");
//        return BOOT_ABORT;
//    }

    const char *img_base = target_includeos_start;
    uint64_t img_size = (uint64_t)target_includeos_end - (uint64_t)img_base;

    Print(L"firestreak: includeos init\n");
    Print(L"firestreak: elf base -> %x\n", img_base);
    Print(L"firestreak: elf size -> %x\n", img_size);

    struct bfelf_binary_t bin;
    platform_memset(&bin, 0U, sizeof(struct bfelf_binary_t));
    char *ptr = platform_alloc_rwe(img_size);
    if (ptr == NULL) {
        Print(L"firestreak: failed to alloc file\n");
        return BOOT_ABORT;
    }

    platform_memcpy(ptr, img_base, img_size);
    bin.file = ptr;
    bin.file_size = img_size;
    int64_t ret = private_load_binary(&bin);
    if (ret != BF_SUCCESS) {
        Print(L"firestreak: failed to load file\n");
        return BOOT_ABORT;
    }

    Print(L"firestreak: exec base -> %x\n", bin.exec);
    Print(L"firestreak: exec size -> %x\n", bin.exec_size);

    struct bfelf_loader_t loader;
    ret = private_relocate_binaries(&bin, 1, &loader);
    if (ret != BF_SUCCESS) {
        Print(L"firestreak: failed to relocate file\n");
        return BOOT_ABORT;
    }

    _start_t entry = 0;
    ret = bfelf_file_get_entry(&bin.ef, (void **)&entry);
    if (ret != BF_SUCCESS) {
        Print(L"firestreak: failed to find entry\n");
        return BOOT_ABORT;
    }

    Print(L"firestreak: includeos entry point: %x\n", entry);
    struct vmcall_regs regs = {0, 0, 0, 0};
    vmcall(&regs);

    return BOOT_CONTINUE;
}

boot_ret_t launch_includeos()
{
    Print(L"firestreak: includeos launch\n");
    return BOOT_CONTINUE;
}

boot_ret_t register_module_firestreak()
{
    boot_add_poststart_fn(init_includeos);
    boot_add_poststart_fn(launch_includeos);

    return BOOT_SUCCESS;
}
