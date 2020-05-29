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
#include <loader_context.h>
#include <loader_debug.h>
#include <loader_platform.h>
#include <loader_types.h>

#include "vmx_util.h"

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for stoping the VMM. This function
 *     will call platform specific functions as needed. Unlike stop_vmm,
 *     this function is called on each CPU.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the id of the cpu to stop
 *   @param context the common context for this cpu
 *   @param arch_context the architecture specific context for this cpu
 *   @return Returns 0 on success
 */
int64_t
arch_stop_vmm_per_cpu(                   // --
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

    if (arch_vmxoff()) {
        BFERROR("VMXOFF failed\n");
        return FAILURE;
    }

    BFDEBUG("Left VMX root operation\n");

    restore_cr4(arch_context);
    restore_cr0(arch_context);

    fini_state_save(arch_context);
    fini_exit_handler_stack(arch_context);
    fini_msr_bitmap_region(arch_context);
    fini_io_bitmap_region(arch_context);
    fini_vmcs_region(arch_context);
    fini_vmxon_region(arch_context);

    return 0;
}
