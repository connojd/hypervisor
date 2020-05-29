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

#include <loader_debug.h>
#include <loader_intrinsics.h>
#include <loader_state_save.h>
#include <loader_types.h>

#define VMCS_EXIT_REASON 0x4402U
#define VMCS_EXIT_INSN_LENGTH 0x440CU

#define EXIT_REASON_CPUID 10U
#define EXIT_REASON_VMXOFF 26U

void vmcs_resume(void);
void vmcs_promote(void);

static inline uint64_t get_exit_reason(void)
{
    uint64_t reason = 0U;
    arch_vmread(VMCS_EXIT_REASON, &reason);

    return reason & 0xFFFFU;
}

static inline uint64_t get_exit_insn_length(void)
{
    uint64_t length = 0U;
    arch_vmread(VMCS_EXIT_INSN_LENGTH, &length);

    return length;
}

static inline void handle_cpuid(struct state_save_t *state)
{
    uint32_t leaf = state->rax;

    uint32_t eax = state->rax & 0xFFFFFFFFU;
    uint32_t ecx = state->rcx & 0xFFFFFFFFU;
    uint32_t ebx = 0U;
    uint32_t edx = 0U;

    arch_cpuid(&eax, &ebx, &ecx, &edx);

    if (0U == leaf) {
        /* Vendor is BareflankVMM */
        state->rax = eax;
        state->rbx = 0x65726142U;
        state->rcx = 0x4D4D566BU;
        state->rdx = 0x6E616C66U;
    } else {
        state->rax = eax;
        state->rbx = ebx;
        state->rcx = ecx;
        state->rdx = edx;
    }

    state->rip += get_exit_insn_length();
}

static inline void handle_vmxoff(struct state_save_t *state)
{
    vmcs_promote();
}

/**
 * <!-- description -->
 *   @brief Top-level dispatch function for vmexits.
 *
 * <!-- inputs/outputs -->
 *   @param the state save structure of the guest the exit occured on.
 *   @return None. Instead it vmresumes back into the guest.
 */
void handle_vmexit(struct state_save_t *state)
{
    uint64_t reason = get_exit_reason();

    switch (reason) {
    case EXIT_REASON_CPUID:
        handle_cpuid(state);
        break;
    case EXIT_REASON_VMXOFF:
        BFALERT("vmxoff exit\n");
        handle_vmxoff(state);
        break;
    default:
        BFALERT("unhandled exit reason: %llu\n", reason);
        break;
    }

    vmcs_resume();
}
