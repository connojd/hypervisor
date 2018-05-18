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

#ifndef HYP_LOADER_H
#define HYP_LOADER_H

#include "bfefi.h"

/**
 * Extendable boot data
 */
struct boot_data {
    /**
     * Handle for this image received from firmware
     */
    EFI_HANDLE this_image;

    /**
     * System table pointer received from firmware
     */
    EFI_SYSTEM_TABLE *sys_table;

    /**
     * Opaque data for downstream users
     */
    void *data;
};

extern struct boot_data g_boot_data;

/**
 * Prestart functions
 */
#ifndef NR_PRESTART_FNS
#define NR_PRESTART_FNS 1U
#endif
typedef void (*prestart_fn_t)(struct boot_data *);
extern prestart_fn_t prestart_fns[NR_PRESTART_FNS];

/**
 * Start functions
 */
#ifndef NR_START_FNS
#define NR_START_FNS 1U
#endif
typedef void (*start_fn_t)(struct boot_data *);
extern start_fn_t start_fns[NR_START_FNS];

/**
 * Poststart functions
 */
#ifndef NR_POSTSTART_FNS
#define NR_POSTSTART_FNS 1U
#endif
typedef void (*poststart_fn_t)(struct boot_data *);
extern poststart_fn_t poststart_fns[NR_POSTSTART_FNS];

/**
 * EFI_MP_SERVICES_PROTOCOL *g_mp_services;
 *
 * Globally accessible pointer to EFI_MP_SERVICES_PROTOCOL interface
 */
extern EFI_MP_SERVICES_PROTOCOL *g_mp_services;

/**
 * Get keystroke
 *
 * Wait for keystroke from user
 *
 * @param key IN/OUT:
 * @return EFI_STATUS EFI_SUCCESS if successful
 */
EFI_STATUS console_get_keystroke(EFI_INPUT_KEY *key);

/**
 * Boot next image by order
 *
 * Boots the image after this one in BootOrder variable.  Not really necessary unless
 * we find firmware that doesn't do this automatically when this image returns EFI_NOT_FOUND
 *
 * @return EFI_STATUS Return status of next image.  Generally doesn't return.
 */
EFI_STATUS bf_boot_next_by_order();

/**
 * bf_start_by_startupallaps()
 *
 * Uses MP services protocol (StartupAllAPs) to launch hypervisor
 * on all cores
 *
 * @return EFI_STATUS EFI_SUCCESS on success
 */
EFI_STATUS bf_start_by_startupallaps();

/**
 * add_boot_prestart_fn()
 *
 * Register a prestart function. A prestart function is run
 * in UEFI context, before VMX is enabled.
 *
 * @param fn the prestart function to add
 * @return EFI_STATUS EFI_SUCCESS on success
 */
EFI_STATUS add_boot_prestart_fn(prestart_fn_t fn);

/**
 * add_boot_start_fn()
 *
 * Register a start function. On success, the start function
 * will return with VMX enabled, and hence any subsequent callers
 * will execute in VMX-nonroot mode.
 *
 * @param fn the start function to add
 * @return EFI_STATUS EFI_SUCCESS on success
 */
EFI_STATUS add_boot_start_fn(start_fn_t fn);

/**
 * add_boot_poststart_fn()
 *
 * Register a poststart function. The poststart function runs
 * after the start_fn returns, and will execute in VMX-nonroot mode.
 *
 * @param fn the poststart function to add
 * @return EFI_STATUS EFI_SUCCESS on success
 */
EFI_STATUS add_boot_poststart_fn(poststart_fn_t fn);

/**
 * register_modules()
 *
 * Call the register_module() function defined by each user extension.
 */
void register_modules();

#endif
