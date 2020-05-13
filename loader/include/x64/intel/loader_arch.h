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

#ifndef LOADER_ARCH_H
#define LOADER_ARCH_H

#include <loader_types.h>

struct loader_arch_context;

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for initializing the loader. This
 *     function will call platform specific functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t arch_loader_init(void);

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for finalizing the loader. This
 *     function will call platform specific functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t arch_loader_fini(void);

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for starting the VMM. This function
 *     will call platform specific functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t arch_start_vmm(void);

/**
 * <!-- description -->
 *   @brief This function contains all of the code that is arch specific
 *     while common between all platforms for stoping the VMM. This function
 *     will call platform specific functions as needed.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t arch_stop_vmm(void);

/**
 * <!-- description -->
 *   @brief This function checks to see if Intel VT-x support is available on
 *     the currently running CPU
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success
 */
int64_t arch_check_hvm_support(void);

/**
 * <!-- description -->
 *   @brief This function prepares the context structure. The context
 *     structure stores all of the pre-vcpu state that the loader is
 *     responsible for setting up. This context structure will be shared
 *     with the kernel which will use it to virtualize the root vCPUs.
 *
 * <!-- inputs/outputs -->
 *   @return Returns a pointer to a loader_arch_content structure on
 *     success. Returns NULL on failure.
 */
int64_t arch_prepare_context(struct loader_arch_context *context);

#endif
