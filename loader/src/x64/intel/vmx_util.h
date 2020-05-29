/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <loader_arch_context.h>
#include <loader_intrinsics.h>
#include <loader_platform.h>
#include <loader_state_save.h>
#include <loader_types.h>

#define PAGE_SIZE 0x1000U           /* 4KB page */
#define STACK_SIZE (4U * PAGE_SIZE) /* 16KB stack */

#define MSR_IA32_FEATURE_CTRL 0x3AU
#define FEATURE_CTRL_LOCKED (1ULL << 0U)
#define FEATURE_CTRL_VMX_ENABLED_INSIDE_SMX (1ULL << 1U)
#define FEATURE_CTRL_VMX_ENABLED_OUTSIDE_SMX (1ULL << 2U)

#define VMX_BASIC_SIZE_MASK 0x1FFF00000000U
#define VMX_BASIC_SIZE_FROM 32U

#define CPUID_LEAF_ADDR_SIZE 0x80000008U
#define CR4_VMXE (1U << 13U)

#define SEGMENT_UNUSABLE 0x10000U
#define TSS_BUSY 0xBU

#define IA32_SYSENTER_CS 0x174U
#define IA32_SYSENTER_ESP 0x175U
#define IA32_SYSENTER_EIP 0x176U
#define IA32_DEBUGCTL 0x1D9U
#define IA32_PAT 0x277U
#define IA32_PERF_GLOBAL_CTRL 0x38FU
#define IA32_EFER    0xC0000080U
#define IA32_FS_BASE 0xC0000100U
#define IA32_GS_BASE 0xC0000101U

#define IA32_VMX_BASIC 0x480U
#define IA32_VMX_MISC 0x485U
#define IA32_VMX_CR0_FIXED0 0x486U
#define IA32_VMX_CR0_FIXED1 0x487U
#define IA32_VMX_CR4_FIXED0 0x488U
#define IA32_VMX_CR4_FIXED1 0x489U

#define IA32_VMX_PROCBASED_CTLS2 0x48BU
#define IA32_VMX_TRUE_PINBASED_CTLS 0x48DU
#define IA32_VMX_TRUE_PROCBASED_CTLS 0x48EU
#define IA32_VMX_TRUE_EXIT_CTLS 0x48FU
#define IA32_VMX_TRUE_ENTRY_CTLS 0x490U

#define VMCS_GUEST_ES_SELECTOR 0x800U
#define VMCS_GUEST_CS_SELECTOR 0x802U
#define VMCS_GUEST_SS_SELECTOR 0x804U
#define VMCS_GUEST_DS_SELECTOR 0x806U
#define VMCS_GUEST_FS_SELECTOR 0x808U
#define VMCS_GUEST_GS_SELECTOR 0x80AU
#define VMCS_GUEST_LDTR_SELECTOR 0x80CU
#define VMCS_GUEST_TR_SELECTOR 0x80EU

#define VMCS_HOST_ES_SELECTOR 0xC00U
#define VMCS_HOST_CS_SELECTOR 0xC02U
#define VMCS_HOST_SS_SELECTOR 0xC04U
#define VMCS_HOST_DS_SELECTOR 0xC06U
#define VMCS_HOST_FS_SELECTOR 0xC08U
#define VMCS_HOST_GS_SELECTOR 0xC0AU
#define VMCS_HOST_TR_SELECTOR 0xC0CU

#define VMCS_IO_BITMAP_A 0x2000U
#define VMCS_IO_BITMAP_B 0x2002U
#define VMCS_MSR_BITMAP 0x2004U
#define VMCS_LINK_POINTER 0x2800U

#define VMCS_GUEST_IA32_DEBUGCTL 0x2802U
#define VMCS_GUEST_IA32_PAT 0x2804U
#define VMCS_GUEST_IA32_EFER 0x2806U
#define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL 0x2808U

#define VMCS_HOST_IA32_PAT 0x2C00U
#define VMCS_HOST_IA32_EFER 0x2C02U
#define VMCS_HOST_IA32_PERF_GLOBAL_CTRL 0x2C04U

#define VMCS_PIN_CTLS 0x4000U
#define VMCS_PROC_CTLS 0x4002U
#define VMCS_PROC2_CTLS 0x401EU
#define VMCS_EXIT_CTLS 0x400CU
#define VMCS_ENTRY_CTLS 0x4012U

#define VMCS_VM_INSN_ERROR 0x4400U

#define VMCS_GUEST_ES_LIMIT 0x4800U
#define VMCS_GUEST_CS_LIMIT 0x4802U
#define VMCS_GUEST_SS_LIMIT 0x4804U
#define VMCS_GUEST_DS_LIMIT 0x4806U
#define VMCS_GUEST_FS_LIMIT 0x4808U
#define VMCS_GUEST_GS_LIMIT 0x480AU
#define VMCS_GUEST_LDTR_LIMIT 0x480CU
#define VMCS_GUEST_TR_LIMIT 0x480EU
#define VMCS_GUEST_GDTR_LIMIT 0x4810U
#define VMCS_GUEST_IDTR_LIMIT 0x4812U

#define VMCS_GUEST_ES_ACCESS_RIGHTS 0x4814U
#define VMCS_GUEST_CS_ACCESS_RIGHTS 0x4816U
#define VMCS_GUEST_SS_ACCESS_RIGHTS 0x4818U
#define VMCS_GUEST_DS_ACCESS_RIGHTS 0x481AU
#define VMCS_GUEST_FS_ACCESS_RIGHTS 0x481CU
#define VMCS_GUEST_GS_ACCESS_RIGHTS 0x481EU
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS 0x4820U
#define VMCS_GUEST_TR_ACCESS_RIGHTS 0x4822U
#define VMCS_GUEST_IA32_SYSENTER_CS 0x482AU

#define VMCS_HOST_IA32_SYSENTER_CS 0x4C00U

#define VMCS_CR0_GUEST_HOST_MASK 0x6000U
#define VMCS_CR4_GUEST_HOST_MASK 0x6002U
#define VMCS_CR0_READ_SHADOW 0x6004U
#define VMCS_CR4_READ_SHADOW 0x6006U

#define VMCS_GUEST_CR0 0x6800U
#define VMCS_GUEST_CR3 0x6802U
#define VMCS_GUEST_CR4 0x6804U
#define VMCS_GUEST_ES_BASE 0x6806U
#define VMCS_GUEST_CS_BASE 0x6808U
#define VMCS_GUEST_SS_BASE 0x680AU
#define VMCS_GUEST_DS_BASE 0x680CU
#define VMCS_GUEST_FS_BASE 0x680EU
#define VMCS_GUEST_GS_BASE 0x6810U
#define VMCS_GUEST_LDTR_BASE 0x6812U
#define VMCS_GUEST_TR_BASE 0x6814U
#define VMCS_GUEST_GDTR_BASE 0x6816U
#define VMCS_GUEST_IDTR_BASE 0x6818U
#define VMCS_GUEST_DR7 0x681AU
#define VMCS_GUEST_RSP 0x681CU
#define VMCS_GUEST_RIP 0x681EU
#define VMCS_GUEST_RFLAGS 0x6820U
#define VMCS_GUEST_IA32_SYSENTER_ESP 0x6824U
#define VMCS_GUEST_IA32_SYSENTER_EIP 0x6826U

#define VMCS_HOST_CR0 0x6C00U
#define VMCS_HOST_CR3 0x6C02U
#define VMCS_HOST_CR4 0x6C04U
#define VMCS_HOST_FS_BASE 0x6C06U
#define VMCS_HOST_GS_BASE 0x6C08U
#define VMCS_HOST_TR_BASE 0x6C0AU
#define VMCS_HOST_GDTR_BASE 0x6C0CU
#define VMCS_HOST_IDTR_BASE 0x6C0EU
#define VMCS_HOST_IA32_SYSENTER_ESP 0x6C10U
#define VMCS_HOST_IA32_SYSENTER_EIP 0x6C12U
#define VMCS_HOST_RSP 0x6C14U
#define VMCS_HOST_RIP 0x6C16U

#define PIN_CTL_EXT_INTR_EXITING (1U << 0U)
#define PIN_CTL_NMI_EXITING (1U << 3U)
#define PIN_CTL_VIRTUAL_NMIS (1U << 5U)

#define PROC_CTL_USE_IO_BITMAPS (1U << 25U)
#define PROC_CTL_USE_MSR_BITMAPS (1U << 28U)
#define PROC_CTL_ACTIVATE_PROC2_CTLS (1U << 31U)

#define PROC2_CTL_ENABLE_RDTSCP (1U << 3U)
#define PROC2_CTL_ENABLE_INVPCID (1U << 12U)
#define PROC2_CTL_ENABLE_XSAVES (1U << 20U)

#define EXIT_CTL_SAVE_DEBUG_CTLS (1U << 2U)
#define EXIT_CTL_HOST_ADDR_SPACE_SIZE (1U << 9U)
#define EXIT_CTL_LOAD_IA32_PERF_GLOBAL_CTRL (1U << 12U)
#define EXIT_CTL_SAVE_IA32_PAT (1U << 18U)
#define EXIT_CTL_LOAD_IA32_PAT (1U << 19U)
#define EXIT_CTL_SAVE_IA32_EFER (1U << 20U)
#define EXIT_CTL_LOAD_IA32_EFER (1U << 21U)

#define ENTRY_CTL_LOAD_DEBUG_CTLS (1U << 2U)
#define ENTRY_CTL_IA32E_MODE_GUEST (1U << 9U)
#define ENTRY_CTL_LOAD_IA32_PERF_GLOBAL_CTRL (1U << 13U)
#define ENTRY_CTL_LOAD_IA32_PAT (1U << 14U)
#define ENTRY_CTL_LOAD_IA32_EFER (1U << 15U)

static inline size_t
vmx_region_size(const struct loader_arch_context_t *ctx)
{
    uint64_t basic = ctx->ia32_vmx_basic;
    return (basic & VMX_BASIC_SIZE_MASK) >> VMX_BASIC_SIZE_FROM;
}

static inline size_t
vmxon_size(const struct loader_arch_context_t *ctx)
{
    return vmx_region_size(ctx);
}

static inline size_t
vmcs_size(const struct loader_arch_context_t *ctx)
{
    return vmx_region_size(ctx);
}

static inline size_t
io_bitmap_size(void)
{
    return PAGE_SIZE;
}

static inline size_t
msr_bitmap_size(void)
{
    return PAGE_SIZE;
}

static inline void
free_vmx_memory(void *virt, size_t size)
{
    platform_free(virt, size);
}

static inline void
fini_vmxon_region(struct loader_arch_context_t *ctx)
{
    free_vmx_memory((void *)ctx->vmxon_virt, vmxon_size(ctx));

    ctx->vmxon_virt = 0U;
    ctx->vmxon_phys = 0U;
}

static inline void
fini_vmcs_region(struct loader_arch_context_t *ctx)
{
    free_vmx_memory((void *)ctx->vmcs_virt, vmcs_size(ctx));

    ctx->vmcs_virt = 0U;
    ctx->vmcs_phys = 0U;
}

static inline void
fini_io_bitmap_region(struct loader_arch_context_t *ctx)
{
    size_t size = io_bitmap_size();

    free_vmx_memory((void *)ctx->io_bitmap_a_virt, size);
    free_vmx_memory((void *)ctx->io_bitmap_b_virt, size);

    ctx->io_bitmap_a_virt = 0U;
    ctx->io_bitmap_a_phys = 0U;

    ctx->io_bitmap_b_virt = 0U;
    ctx->io_bitmap_b_phys = 0U;
}

static inline void
fini_msr_bitmap_region(struct loader_arch_context_t *ctx)
{
    free_vmx_memory((void *)ctx->msr_bitmap_virt, msr_bitmap_size());

    ctx->msr_bitmap_virt = 0U;
    ctx->msr_bitmap_phys = 0U;
}

static inline void
restore_cr0(struct loader_arch_context_t *ctx)
{
    if (ctx->old_cr0 != ctx->new_cr0) {
        arch_writecr0(ctx->old_cr0);
    }
}

static inline void
restore_cr4(struct loader_arch_context_t *ctx)
{
    if (ctx->old_cr4 != ctx->new_cr4) {
        arch_writecr4(ctx->old_cr4);
    }
}

static inline void
fini_exit_handler_stack(struct loader_arch_context_t *ctx)
{
    platform_free((void *)ctx->exit_handler_stack, STACK_SIZE);
}

static inline void
fini_state_save(struct loader_arch_context_t *ctx)
{
    platform_free((void *)ctx->state_save, sizeof(struct state_save_t));
}
