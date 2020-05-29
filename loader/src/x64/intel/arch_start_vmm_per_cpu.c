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

#include <loader_arch.h>
#include <loader_arch_context.h>
#include <loader_check_canonical.h>
#include <loader_check_page_aligned.h>
#include <loader_check_valid_physical.h>
#include <loader_context.h>
#include <loader_debug.h>
#include <loader_gdt.h>
#include <loader_idt.h>
#include <loader_intrinsics.h>
#include <loader_platform.h>
#include <loader_state_save.h>
#include <loader_types.h>

#include "vmx_util.h"

void exit_handler_entry(void);
uint64_t vmcs_launch(void);

static void vmwrite(uint64_t field, uint64_t value)
{
    if (arch_vmwrite(field, value)) {
        BFERROR("vmwrite failed: field 0x%llx value 0x%llx\n", field, value);
    } else {
        printk("field 0x%llx value 0x%llx\n", field, value);
    }
}

static int64_t alloc_vmx_memory(size_t size,
                                const struct loader_arch_context_t *ctx,
                                uintptr_t *virt,
                                uintptr_t *phys)
{
    uintptr_t va = 0U;
    uintptr_t pa = 0U;

    if (NULL == ctx) {
        BFALERT("ctx is NULL\n");
        return FAILURE;
    }

    if (NULL == virt) {
        BFALERT("virt is NULL\n");
        return FAILURE;
    }

    if (NULL == phys) {
        BFALERT("phys is NULL\n");
        return FAILURE;
    }

    va = (uintptr_t)platform_alloc(size);
    if (0U == va) {
        BFALERT("platform_alloc failed\n");
        return FAILURE;
    }

    pa = platform_virt_to_phys(va);
    if (0U == pa) {
        BFALERT("platform_virt_to_phys failed\n");
        platform_free((void *)va, size);
        return FAILURE;
    }

    if (check_page_aligned(pa, ctx)) {
        BFALERT("physical address is not page aligned\n");
        platform_free((void *)va, size);
        return FAILURE;
    }

    if (check_valid_physical(pa, ctx)) {
        BFALERT("physical address is not valid\n");
        platform_free((void *)va, size);
        return FAILURE;
    }

    *virt = va;
    *phys = pa;

    return 0;
}

static int64_t
init_vmxon_region(struct loader_arch_context_t *ctx)
{
    uintptr_t virt = 0U;
    uintptr_t phys = 0U;

    size_t size = vmxon_size(ctx);

    if (alloc_vmx_memory(size, ctx, &virt, &phys)) {
        BFERROR("failed to alloc vmxon region\n");
        return FAILURE;
    }

    /*
     * From section 24.11.5 in the SDM:
     *
     * Before executing VMXON, software should write the 31-bit VMCS revision
     * identifier to bits 30:0 of the first 4 bytes of the VMXON region; bit 31
     * should be cleared to 0. It need not initialize the VMXON region in any
     * other way.
     */

    ctx->vmxon_phys = phys;
    ctx->vmxon_virt = (uint32_t *)virt;
    ctx->vmxon_virt[0] = ctx->ia32_vmx_basic & 0x7FFFFFFFU;

    return 0;
}

static int64_t
init_vmcs_region(struct loader_arch_context_t *ctx)
{
    uintptr_t virt = 0U;
    uintptr_t phys = 0U;

    size_t size = vmcs_size(ctx);

    if (alloc_vmx_memory(size, ctx, &virt, &phys)) {
        BFERROR("failed to alloc vmcs region\n");
        return FAILURE;
    }

    platform_memset((void *)virt, 0, size);

    /*
     * The VMCS region is intialized in a similar manner to the VMXON region
     * above, however the meaning of bit 31 in the VMCS region indicates a
     * shadow VMCS. This bit is always cleared from this loader.
     */

    ctx->vmcs_phys = phys;
    ctx->vmcs_virt = (uint32_t *)virt;
    ctx->vmcs_virt[0] = ctx->ia32_vmx_basic & 0x7FFFFFFFU;

    return 0;
}

static int64_t
init_io_bitmap_region(struct loader_arch_context_t *ctx)
{
    uintptr_t a_virt = 0U;
    uintptr_t a_phys = 0U;
    uintptr_t b_virt = 0U;
    uintptr_t b_phys = 0U;

    size_t size = io_bitmap_size();

    if (alloc_vmx_memory(size, ctx, &a_virt, &a_phys)) {
        BFALERT("failed to allocate io bitmap a region\n");
        return FAILURE;
    }

    if (alloc_vmx_memory(size, ctx, &b_virt, &b_phys)) {
        BFALERT("failed to allocate io bitmap b region\n");
        free_vmx_memory((void *)a_virt, size);
        return FAILURE;
    }

    ctx->io_bitmap_a_phys = a_phys;
    ctx->io_bitmap_a_virt = (uint8_t *)a_virt;

    ctx->io_bitmap_b_phys = b_phys;
    ctx->io_bitmap_b_virt = (uint8_t *)b_virt;

    /*
     * Clear the I/O bitmaps. This implies no I/O instructions will exit when
     * the "use I/O bitmaps" execution control is 1 in the vmcs.
     */

    platform_memset((void *)ctx->io_bitmap_a_virt, 0, size);
    platform_memset((void *)ctx->io_bitmap_b_virt, 0, size);

    return 0;
}

static int64_t
init_msr_bitmap_region(struct loader_arch_context_t *ctx)
{
    uintptr_t virt = 0U;
    uintptr_t phys = 0U;

    size_t size = msr_bitmap_size();

    if (alloc_vmx_memory(size, ctx, &virt, &phys)) {
        BFALERT("failed to alloc msr bitmap region\n");
        return FAILURE;
    }

    ctx->msr_bitmap_phys = phys;
    ctx->msr_bitmap_virt = (uint8_t *)virt;

    /*
     * Clear the MSR bitmaps. This implies RDMSR/WRMSR will never trap when
     * the "use MSR bitmaps" execution control is 1 in the vmcs.
     */

    platform_memset((void *)ctx->msr_bitmap_virt, 0, size);

    return 0;
}

static int64_t
init_exit_handler_stack(struct loader_arch_context_t *ctx)
{
    uintptr_t virt = (uintptr_t)platform_alloc(STACK_SIZE);

    if (0U == virt) {
        BFERROR("failed to alloc exit handler stack\n");
        return FAILURE;
    }

    ctx->exit_handler_stack = (uint8_t *)virt;

    return 0;
}

static int64_t
init_state_save(struct loader_arch_context_t *ctx)
{
    uintptr_t virt = (uintptr_t)platform_alloc(sizeof(struct state_save_t));

    if (0U == virt) {
        BFERROR("failed to alloc state save region\n");
        return FAILURE;
    }

    ctx->state_save = (struct state_save_t *)virt;
    ctx->state_save->vcpu_ptr = virt;

    return 0;
}

static int64_t
prepare_cr0_for_vmx(struct loader_arch_context_t *ctx)
{
    uint64_t cr0_fixed0 = 0U;
    uint64_t cr0_fixed1 = 0U;

    ctx->old_cr0 = arch_readcr0();
    ctx->new_cr0 = ctx->old_cr0;

    ctx->ia32_vmx_cr0_fixed0 = arch_rdmsr(IA32_VMX_CR0_FIXED0);
    ctx->ia32_vmx_cr0_fixed1 = arch_rdmsr(IA32_VMX_CR0_FIXED1);

    cr0_fixed1 = ctx->ia32_vmx_cr0_fixed0;
    cr0_fixed0 = ~ctx->ia32_vmx_cr0_fixed1;

    if ((cr0_fixed1 & ctx->old_cr0) != cr0_fixed1) {
        BFDEBUG("setting bits 0x%llx in cr0\n", cr0_fixed1 & ~ctx->old_cr0);
    }

    if ((cr0_fixed0 & ~ctx->old_cr0) != cr0_fixed0) {
        BFDEBUG("clearing bits 0x%llx in cr0\n", cr0_fixed0 & ctx->old_cr0);
    }

    ctx->new_cr0 |= cr0_fixed1;
    ctx->new_cr0 &= ~cr0_fixed0;

    return 0;
}

static int64_t
prepare_cr4_for_vmx(struct loader_arch_context_t *ctx)
{
    uint64_t cr4_fixed0 = 0U;
    uint64_t cr4_fixed1 = 0U;

    ctx->old_cr4 = arch_readcr4();

    if ((ctx->old_cr4 & CR4_VMXE) != 0U) {
        BFERROR("CR4.VMXE is already enabled. Is another vmm running?\n");
        return FAILURE;
    }

    ctx->new_cr4 = ctx->old_cr4;

    ctx->ia32_vmx_cr4_fixed0 = arch_rdmsr(IA32_VMX_CR4_FIXED0);
    ctx->ia32_vmx_cr4_fixed1 = arch_rdmsr(IA32_VMX_CR4_FIXED1);

    cr4_fixed1 = ctx->ia32_vmx_cr4_fixed0;
    cr4_fixed0 = ~ctx->ia32_vmx_cr4_fixed1;

    if ((cr4_fixed1 & ctx->old_cr4) != cr4_fixed1) {
        BFDEBUG("setting bits 0x%016llx in cr4\n", cr4_fixed1 & ~ctx->old_cr4);
    }

    if ((cr4_fixed0 & ~ctx->old_cr4) != cr4_fixed0) {
        BFDEBUG("clearing bits 0x%llx in cr4\n", cr4_fixed0 & ctx->old_cr4);
    }

    ctx->new_cr4 |= cr4_fixed1;
    ctx->new_cr4 &= ~cr4_fixed0;

    return 0;
}

static inline void
commit_cr0_for_vmx(const struct loader_arch_context_t *ctx)
{
    if (ctx->old_cr0 != ctx->new_cr0) {
        arch_writecr0(ctx->new_cr0);
    }
}

static inline void
commit_cr4_for_vmx(const struct loader_arch_context_t *ctx)
{
    if (ctx->old_cr4 != ctx->new_cr4) {
        arch_writecr4(ctx->new_cr4);
    }
}

static inline void
get_address_bits(struct loader_arch_context_t *ctx)
{
    uint32_t eax = CPUID_LEAF_ADDR_SIZE;
    uint32_t ebx = 0U;
    uint32_t ecx = 0U;
    uint32_t edx = 0U;

    arch_cpuid(&eax, &ebx, &ecx, &edx);

    ctx->phys_address_bits = eax & 0xFFU;
    ctx->virt_address_bits = (eax & 0xFF00U) >> 8U;
}

static inline void
lock_vmx_operation(void)
{
    uint64_t msr = arch_rdmsr(MSR_IA32_FEATURE_CTRL);

    if ((msr & FEATURE_CTRL_LOCKED) != 0U) {
        return;
    }

    if ((msr & FEATURE_CTRL_VMX_ENABLED_OUTSIDE_SMX) == 0U) {
        msr |= FEATURE_CTRL_VMX_ENABLED_OUTSIDE_SMX;
    }

    msr |= FEATURE_CTRL_LOCKED;
    arch_wrmsr(MSR_IA32_FEATURE_CTRL, msr);
}

static int64_t
init_vmcs_control_fields(struct loader_arch_context_t *ctx)
{
    uint64_t msr_true_pin = arch_rdmsr(IA32_VMX_TRUE_PINBASED_CTLS);
    uint64_t msr_true_proc = arch_rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS);
    uint64_t msr_true_exit = arch_rdmsr(IA32_VMX_TRUE_EXIT_CTLS);
    uint64_t msr_true_entry = arch_rdmsr(IA32_VMX_TRUE_ENTRY_CTLS);

    uint64_t ctl_pin = (msr_true_pin & 0xFFFFFFFFU) & (msr_true_pin >> 32U);
    uint64_t ctl_proc = (msr_true_proc & 0xFFFFFFFFU) & (msr_true_proc >> 32U);
    uint64_t ctl_exit = (msr_true_exit & 0xFFFFFFFFU) & (msr_true_exit >> 32U);
    uint64_t ctl_entry = (msr_true_entry & 0xFFFFFFFFU) & (msr_true_entry >> 32U);
    uint64_t ctl_proc2 = 0U;

    if (NULL == ctx) {
        BFERROR("invalid arch_context\n");
        return FAILURE;
    }

    ctl_proc |= PROC_CTL_USE_IO_BITMAPS;
    ctl_proc |= PROC_CTL_USE_MSR_BITMAPS;
    ctl_proc |= PROC_CTL_ACTIVATE_PROC2_CTLS;

    ctl_exit |= EXIT_CTL_SAVE_DEBUG_CTLS;
    ctl_exit |= EXIT_CTL_HOST_ADDR_SPACE_SIZE;
    ctl_exit |= EXIT_CTL_LOAD_IA32_PERF_GLOBAL_CTRL;
    ctl_exit |= EXIT_CTL_SAVE_IA32_PAT;
    ctl_exit |= EXIT_CTL_LOAD_IA32_PAT;
    ctl_exit |= EXIT_CTL_SAVE_IA32_EFER;
    ctl_exit |= EXIT_CTL_LOAD_IA32_EFER;

    ctl_entry |= ENTRY_CTL_LOAD_DEBUG_CTLS;
    ctl_entry |= ENTRY_CTL_IA32E_MODE_GUEST;
    ctl_entry |= ENTRY_CTL_LOAD_IA32_PERF_GLOBAL_CTRL;
    ctl_entry |= ENTRY_CTL_LOAD_IA32_PAT;
    ctl_entry |= ENTRY_CTL_LOAD_IA32_EFER;

    ctl_proc2 |= PROC2_CTL_ENABLE_RDTSCP;
    ctl_proc2 |= PROC2_CTL_ENABLE_INVPCID;
    ctl_proc2 |= PROC2_CTL_ENABLE_XSAVES;

    vmwrite(VMCS_IO_BITMAP_A, ctx->io_bitmap_a_phys);
    vmwrite(VMCS_IO_BITMAP_B, ctx->io_bitmap_b_phys);
    vmwrite(VMCS_MSR_BITMAP, ctx->msr_bitmap_phys);

    vmwrite(VMCS_PIN_CTLS, ctl_pin);
    vmwrite(VMCS_PROC_CTLS, ctl_proc);
    vmwrite(VMCS_EXIT_CTLS, ctl_exit);
    vmwrite(VMCS_ENTRY_CTLS, ctl_entry);
    vmwrite(VMCS_PROC2_CTLS, ctl_proc2);

    vmwrite(VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFU);

    return 0;
}

static int64_t
init_vmcs_guest_fields(struct loader_arch_context_t *ctx)
{
    uint16_t es_selector = arch_reades();
    uint16_t cs_selector = arch_readcs();
    uint16_t ss_selector = arch_readss();
    uint16_t ds_selector = arch_readds();
    uint16_t fs_selector = arch_readfs();
    uint16_t gs_selector = arch_readgs();
    uint16_t ldtr_selector = arch_readldtr();
    uint16_t tr_selector = arch_readtr();

    uint16_t es_index = es_selector >> 3U;
    uint16_t cs_index = cs_selector >> 3U;
    uint16_t ss_index = ss_selector >> 3U;
    uint16_t ds_index = ds_selector >> 3U;
    uint16_t fs_index = fs_selector >> 3U;
    uint16_t gs_index = gs_selector >> 3U;
    uint16_t ldtr_index = ldtr_selector >> 3U;
    uint16_t tr_index = tr_selector >> 3U;

    struct global_descriptor_table_register gdtr = {0};
    struct interrupt_descriptor_table_register idtr = {0};

    printk("TR_INDEX: 0x%x\n", tr_index);

    if (NULL == ctx) {
        BFERROR("invalid arch context\n");
        return FAILURE;
    }

    vmwrite(VMCS_GUEST_ES_SELECTOR, es_selector);
    vmwrite(VMCS_GUEST_CS_SELECTOR, cs_selector);
    vmwrite(VMCS_GUEST_SS_SELECTOR, ss_selector);
    vmwrite(VMCS_GUEST_DS_SELECTOR, ds_selector);
    vmwrite(VMCS_GUEST_FS_SELECTOR, fs_selector);
    vmwrite(VMCS_GUEST_GS_SELECTOR, gs_selector);
    vmwrite(VMCS_GUEST_LDTR_SELECTOR, ldtr_selector);
    vmwrite(VMCS_GUEST_TR_SELECTOR, tr_selector);
    vmwrite(VMCS_GUEST_IA32_DEBUGCTL, arch_rdmsr(IA32_DEBUGCTL));
    vmwrite(VMCS_GUEST_IA32_PAT, arch_rdmsr(IA32_PAT));
    vmwrite(VMCS_GUEST_IA32_EFER, arch_rdmsr(IA32_EFER));
    vmwrite(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, arch_rdmsr(IA32_PERF_GLOBAL_CTRL));

    arch_sgdt(&gdtr);
    arch_sidt(&idtr);

    if (check_canonical((uintptr_t)gdtr.base, ctx)) {
        BFERROR("gdtr base not canonical\n");
        return FAILURE;
    }

    if (check_canonical((uintptr_t)idtr.base, ctx)) {
        BFERROR("idtr base not canonical\n");
        return FAILURE;
    }

    vmwrite(VMCS_GUEST_GDTR_BASE, (uintptr_t)gdtr.base);
    vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr.limit);

    vmwrite(VMCS_GUEST_IDTR_BASE, (uintptr_t)idtr.base);
    vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr.limit);

    vmwrite(VMCS_GUEST_ES_LIMIT,
                 get_segment_descriptor_limit(&gdtr, es_index));
    vmwrite(VMCS_GUEST_CS_LIMIT,
                 get_segment_descriptor_limit(&gdtr, cs_index));
    vmwrite(VMCS_GUEST_SS_LIMIT,
                 get_segment_descriptor_limit(&gdtr, ss_index));
    vmwrite(VMCS_GUEST_DS_LIMIT,
                 get_segment_descriptor_limit(&gdtr, ds_index));
    vmwrite(VMCS_GUEST_FS_LIMIT,
                 get_segment_descriptor_limit(&gdtr, fs_index));
    vmwrite(VMCS_GUEST_GS_LIMIT,
                 get_segment_descriptor_limit(&gdtr, gs_index));
    vmwrite(VMCS_GUEST_LDTR_LIMIT,
                 get_segment_descriptor_limit(&gdtr, ldtr_index));
    vmwrite(VMCS_GUEST_TR_LIMIT,
                 get_segment_descriptor_limit(&gdtr, tr_index));

    vmwrite(VMCS_GUEST_ES_BASE,
                 get_segment_descriptor_base(&gdtr, es_index));
    vmwrite(VMCS_GUEST_CS_BASE,
                 get_segment_descriptor_base(&gdtr, cs_index));
    vmwrite(VMCS_GUEST_SS_BASE,
                 get_segment_descriptor_base(&gdtr, ss_index));
    vmwrite(VMCS_GUEST_DS_BASE,
                 get_segment_descriptor_base(&gdtr, ds_index));
    vmwrite(VMCS_GUEST_FS_BASE,
                 arch_rdmsr(IA32_FS_BASE));
    vmwrite(VMCS_GUEST_GS_BASE,
                 arch_rdmsr(IA32_GS_BASE));
    vmwrite(VMCS_GUEST_LDTR_BASE,
                 get_segment_descriptor_base(&gdtr, ldtr_index));
    vmwrite(VMCS_GUEST_TR_BASE,
                 get_segment_descriptor_base(&gdtr, tr_index));

    vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS,
                 (es_index != 0U)
                 ? get_segment_descriptor_attrib(&gdtr, es_index)
                 : SEGMENT_UNUSABLE);
    vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS,
                 (cs_index != 0U)
                 ? get_segment_descriptor_attrib(&gdtr, cs_index)
                 : SEGMENT_UNUSABLE);
    vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS,
                 (ss_index != 0U)
                 ? get_segment_descriptor_attrib(&gdtr, ss_index)
                 : SEGMENT_UNUSABLE);
    vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS,
                 (ds_index != 0U)
                 ? get_segment_descriptor_attrib(&gdtr, ds_index)
                 : SEGMENT_UNUSABLE);
    vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS,
                 (fs_index != 0U)
                 ? get_segment_descriptor_attrib(&gdtr, fs_index)
                 : SEGMENT_UNUSABLE);
    vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS,
                 (gs_index != 0U)
                 ? get_segment_descriptor_attrib(&gdtr, gs_index)
                 : SEGMENT_UNUSABLE);
    vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS,
                 (ldtr_index != 0U)
                 ? get_segment_descriptor_attrib(&gdtr, ldtr_index)
                 : SEGMENT_UNUSABLE);
    vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS,
                 (tr_index != 0U)
                 ? get_segment_descriptor_attrib(&gdtr, tr_index)
                 : (TSS_BUSY | 0x80U));

    /*
     * For now we dont trap on any cr0/cr4 writes. This is obviously unsafe but
     * for simplicitly we just bury our head and assume the OS will cooperate.
     */
    vmwrite(VMCS_CR0_GUEST_HOST_MASK, 0U);
    vmwrite(VMCS_CR4_GUEST_HOST_MASK, 0U);

    vmwrite(VMCS_GUEST_CR0, arch_readcr0());
    vmwrite(VMCS_GUEST_CR3, arch_readcr3());
    vmwrite(VMCS_GUEST_CR4, arch_readcr4());
    vmwrite(VMCS_GUEST_DR7, arch_readdr7());

    vmwrite(VMCS_GUEST_IA32_SYSENTER_CS, arch_rdmsr(IA32_SYSENTER_CS));
    vmwrite(VMCS_GUEST_IA32_SYSENTER_ESP, arch_rdmsr(IA32_SYSENTER_ESP));
    vmwrite(VMCS_GUEST_IA32_SYSENTER_EIP, arch_rdmsr(IA32_SYSENTER_EIP));

    vmwrite(VMCS_GUEST_RFLAGS, arch_rflags());

    return 0;
}

static int64_t
init_vmcs_host_fields(struct loader_arch_context_t *ctx)
{
    uint16_t es_selector = arch_reades();
    uint16_t cs_selector = arch_readcs();
    uint16_t ss_selector = arch_readss();
    uint16_t ds_selector = arch_readds();
    uint16_t fs_selector = arch_readfs();
    uint16_t gs_selector = arch_readgs();
    uint16_t tr_selector = arch_readtr();
    uint16_t tr_index = tr_selector >> 3U;

    uintptr_t stack_top = (uintptr_t)ctx->exit_handler_stack + STACK_SIZE - 1U;

    struct global_descriptor_table_register gdtr = {0};
    struct interrupt_descriptor_table_register idtr = {0};

    arch_sgdt(&gdtr);
    arch_sidt(&idtr);

    vmwrite(VMCS_HOST_ES_SELECTOR, es_selector);
    vmwrite(VMCS_HOST_CS_SELECTOR, cs_selector);
    vmwrite(VMCS_HOST_SS_SELECTOR, ss_selector);
    vmwrite(VMCS_HOST_DS_SELECTOR, ds_selector);
    vmwrite(VMCS_HOST_FS_SELECTOR, fs_selector);
    vmwrite(VMCS_HOST_GS_SELECTOR, gs_selector);
    vmwrite(VMCS_HOST_TR_SELECTOR, tr_selector);
    vmwrite(VMCS_HOST_IA32_PAT, arch_rdmsr(IA32_PAT));
    vmwrite(VMCS_HOST_IA32_EFER, arch_rdmsr(IA32_EFER));
    vmwrite(VMCS_HOST_IA32_PERF_GLOBAL_CTRL, arch_rdmsr(IA32_PERF_GLOBAL_CTRL));
    vmwrite(VMCS_HOST_IA32_SYSENTER_CS, arch_rdmsr(IA32_SYSENTER_CS));
    vmwrite(VMCS_HOST_CR0, arch_readcr0());
    vmwrite(VMCS_HOST_CR3, arch_readcr3());
    vmwrite(VMCS_HOST_CR4, arch_readcr4());
    vmwrite(VMCS_HOST_FS_BASE, (uintptr_t)ctx->state_save);
    vmwrite(VMCS_HOST_GS_BASE, arch_rdmsr(IA32_GS_BASE));
    vmwrite(VMCS_HOST_TR_BASE, get_segment_descriptor_base(&gdtr, tr_index));
    vmwrite(VMCS_HOST_GDTR_BASE, (uintptr_t)gdtr.base);
    vmwrite(VMCS_HOST_IDTR_BASE, (uintptr_t)idtr.base);
    vmwrite(VMCS_HOST_IA32_SYSENTER_ESP, arch_rdmsr(IA32_SYSENTER_ESP));
    vmwrite(VMCS_HOST_IA32_SYSENTER_EIP, arch_rdmsr(IA32_SYSENTER_EIP));
    vmwrite(VMCS_HOST_RSP, stack_top);
    vmwrite(VMCS_HOST_RIP, (uintptr_t)exit_handler_entry);

    return 0;
}

static int64_t
init_vmcs_fields(struct loader_arch_context_t *ctx)
{
    if (init_vmcs_control_fields(ctx)) {
        BFERROR("failed to init vmcs control fields\n");
        return FAILURE;
    }

    if (init_vmcs_host_fields(ctx)) {
        BFERROR("failed to init vmcs host fields\n");
        return FAILURE;
    }

    if (init_vmcs_guest_fields(ctx)) {
        BFERROR("failed to init vmcs guest fields\n");
        return FAILURE;
    }

    return 0;
}

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for starting the VMM. This function
 *     will call platform specific functions as needed. Unlike start_vmm,
 *     this function is called on each CPU.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the id of the cpu to start
 *   @param context the common context for this cpu
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
arch_start_vmm_per_cpu(                  // --
    uint32_t const cpu,                  // --
    struct loader_context_t *context,    // --
    struct loader_arch_context_t *arch_context)
{
    if (NULL == context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (NULL == arch_context) {
        BFERROR("invalid argument\n");
        return FAILURE;
    }

    if (arch_check_hve_support()) {
        BFERROR("arch_check_hve_support failed\n");
        return FAILURE;
    }

    if (prepare_cr0_for_vmx(arch_context)) {
        return FAILURE;
    }

    if (prepare_cr4_for_vmx(arch_context)) {
        return FAILURE;
    }

    if ((arch_rdmsr(IA32_VMX_MISC) & (1U << 14U)) == 0U) {
        BFALERT("Intel PT may not be used with VT-x\n");
    }

    arch_context->page_size = PAGE_SIZE;
    arch_context->ia32_vmx_basic = arch_rdmsr(IA32_VMX_BASIC);

    get_address_bits(arch_context);

    if (init_vmxon_region(arch_context)) {
        return FAILURE;
    }

    if (init_vmcs_region(arch_context)) {
        goto out_vmxon;
    }

    if (init_io_bitmap_region(arch_context)) {
        goto out_vmcs;
    }

    if (init_msr_bitmap_region(arch_context)) {
        goto out_io_bitmap;
    }

    if (init_exit_handler_stack(arch_context)) {
        goto out_msr_bitmap;
    }

    if (init_state_save(arch_context)) {
        goto out_stack;
    }

    lock_vmx_operation();

    commit_cr0_for_vmx(arch_context);
    commit_cr4_for_vmx(arch_context);

    if (arch_vmxon(&arch_context->vmxon_phys)) {
        BFERROR("vmxon failed\n");
        goto out_crs;
    }

    BFDEBUG("Entered VMX root operation\n");

    if (arch_vmclear(&arch_context->vmcs_phys)) {
        BFERROR("vmclear failed\n");
        goto out_vmxoff;
    }

    if (arch_vmptrld(&arch_context->vmcs_phys)) {
        BFERROR("failed load vmcs\n");
        goto out_vmxoff;
    }

    if (init_vmcs_fields(arch_context)) {
        BFERROR("failed to init vmcs fields\n");
        goto out_vmxoff;
    }

    if (vmcs_launch()) {
        uint64_t err = 0U;

        BFERROR("vmlaunch failed\n");

        switch (arch_vmread(VMCS_VM_INSN_ERROR, &err)) {
        case 0:
            BFERROR("vm insn error: %llu\n", err);
            break;
        case 1:
            BFERROR("vmread failed invalid\n");
            break;
        case 2:
            BFERROR("vmread failed valid\n");
            break;
        default:
            BFERROR("vmread return unexpected\n");
            break;
        }

        return FAILURE;
    }

    BFDEBUG("vmlaunch succeeded\n");

    /*
     * If we make it here, we are now a guest running in VMX non-root operation.
     * Every exit traps to exit_handler_entry, which then calls handle_vmexit.
     * After the specific exit reason has been handled, handle_vmexit calls
     * vmcs_resume to hand execution back to the guest.
     */

    return 0;

out_vmxoff:
    arch_vmxoff();

out_crs:
    restore_cr4(arch_context);
    restore_cr0(arch_context);

    fini_state_save(arch_context);

out_stack:
    fini_exit_handler_stack(arch_context);

out_msr_bitmap:
    fini_msr_bitmap_region(arch_context);

out_io_bitmap:
    fini_io_bitmap_region(arch_context);

out_vmcs:
    fini_vmcs_region(arch_context);

out_vmxon:
    fini_vmxon_region(arch_context);

    return 0;
}
