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

#include "bfefi.h"
#include "bflib.h"
#include "bfloader.h"
#include "common.h"
#include "x86_64.h"

VOID __attribute__((ms_abi)) bf_stop_hypervisor_on_core(VOID *data)
{
    (void)data;
    common_stop_core();
}

VOID __attribute__((ms_abi)) bf_cpuid_on_core(VOID *data)
{
    (void)data;
    __asm("cpuid");
}

//static inline void create_tss()
//{
//    KDESCRIPTOR gdtr;
//    _sgdt((void *)&gdtr.Limit);
//    const UINTN old_size = gdtr.Limit + 1U;
//    uint8_t *old_base = (uint8_t *)gdtr.Base;
//
//    Print(L"sizeof(KTSS64): %llu\n", sizeof(KTSS64));
//    Print(L"sizeof(KGDTENTRY64): %llu\n\n", sizeof(KGDTENTRY64));
//
//    Print(L"Old GDT base: 0x%08x\n", old_base);
//    Print(L"Old GDT size: %llu\n", old_size);
//    Print(L"Old GDT 8-byte entries: %llu\n\n", old_size >> 3U);
//
//    const UINTN new_size = old_size + sizeof(KGDTENTRY64);
//    uint8_t *new_gdt = (uint8_t *)bf_allocate_runtime_zero_pool(new_size);
//    if (new_gdt == NULL) {
//        Print(L"create_busy_tss: failed to alloc new GDT\n");
//        return;
//    }
//
//    uint8_t *new_tss = (uint8_t *)bf_allocate_runtime_zero_pool(sizeof(KTSS64));
//    if (new_tss == NULL) {
//        bf_free_pool(new_gdt);
//        Print(L"create_busy_tss: failed to alloc new TSS\n");
//        return;
//    }
//
//    gBS->CopyMem(new_gdt, old_base, old_size);
//    KGDTENTRY64 *entry = (KGDTENTRY64 *)(new_gdt + old_size);
//    entry->LimitLow = sizeof(KTSS64) & 0xFFFFU;
//    entry->BaseLow = (uintptr_t)new_tss & 0xFFFFU;
//    entry->Bits.BaseMiddle = ((uintptr_t)new_tss >> 16) & 0xFFU;
//    entry->Bits.Type = AMD64_TSS; // non-busy 64-bit TSS
//    entry->Bits.Dpl = 0U;
//    entry->Bits.Present = 1U;
//    entry->Bits.LimitHigh = (sizeof(KTSS64) >> 16) & 0xFU;
//    entry->Bits.System = 0U;
//    entry->Bits.LongMode = 0U;
//    entry->Bits.DefaultBig = 0U;
//    entry->Bits.Granularity = 0U;
//    entry->Bits.BaseHigh = ((uintptr_t)new_tss >> 24) & 0xFFU;
//    entry->BaseUpper = ((uintptr_t)new_tss >> 32) & 0xFFFFFFFFU;
//    entry->MustBeZero = 0U;
//
//    const UINTN new_limit = new_size - 1U;
//    const UINTN nr_64bit_entries = new_size >> 3U;
//    const UINTN tss_index = nr_64bit_entries - 2U;
//    const UINTN tss_selector = tss_index << 3U; // TI = 0, RPL = 0
//
//    gdtr.Base = new_gdt;
//    gdtr.Limit = new_limit;
//
//    Print(L"New GDT base: 0x%08x\n", gdtr.Base);
//    Print(L"New GDT size: %llu\n", new_size);
//    Print(L"New GDT 8-byte entries: %llu\n", nr_64bit_entries);
//    Print(L"New GDT TSS 8-byte offset: %llu\n", tss_index);
//    Print(L"New GDT TSS selector: %llu\n", tss_selector);
//
//    _lgdt((void *)&gdtr.Limit);
//    _ltr(tss_selector);
//}

VOID __attribute__((ms_abi)) bf_start_hypervisor_on_core(VOID *data)
{
    (void)data;

//    create_tss();
    int64_t ret = common_start_core();

    if (ret < 0) {
        Print(L"Error: bf_start_hypervisor_on_core: common_start_core %x\n", ret);
        return;
    }
}

EFI_STATUS inline bf_start_by_startupallaps()
{
//    EFI_STATUS status;
//    UINTN cpus;
//    EFI_MP_SERVICES_PROTOCOL *mp_services;
//
//    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
//    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
//                                 NULL,
//                                 (VOID **)&mp_services);
//    if (EFI_ERROR(status)) {
//        PRINT_ERROR(status);
//        goto fail;
//    }
//
//    cpus = bf_num_cpus();
//    if (cpus == 0) {
//        Print(L"Error: bf_start_by_startupallaps: bf_num_cpus\n");
//        return EFI_NOT_FOUND;
//    }
//    Print(L"Detected %u CPUs.\n", cpus);

    //if (cpus > 1) {
    //    status = mp_services->StartupAllAPs(mp_services,
    //                                        (EFI_AP_PROCEDURE)bf_start_hypervisor_on_core,
    //                                        TRUE,
    //                                        NULL,
    //                                        10000000,
    //                                        NULL,
    //                                        NULL);
    //    if (EFI_ERROR(status)) {
    //        PRINT_ERROR(status);
    //        goto fail;
    //    }
    //}

    bf_start_hypervisor_on_core(NULL);

//    Print(L"Core started\n");
    return EFI_SUCCESS;

//fail:
//    Print(L"Failed to run start on core\n");
//    return EFI_ABORTED;
//
}


EFI_STATUS bf_start_by_switchbsp()
{
    EFI_STATUS status;
    UINTN cpus;
    EFI_MP_SERVICES_PROTOCOL *mp_services;

    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&mp_services);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    cpus = bf_num_cpus();
    if (cpus == 0) {
        Print(L"Error: bf_start_by_switchbsp: bf_num_cpus\n");
        return EFI_NOT_FOUND;
    }
    Print(L"Detected %u CPUs.\n", cpus);

    if (cpus > 1) {
        UINTN cur = cpus - 1;
        while (cur > 0) {
            status = mp_services->SwitchBSP(mp_services,
                                            cur,
                                            TRUE);
            if (EFI_ERROR(status)) {
                PRINT_ERROR(status);
                goto fail;
            }

            bf_start_hypervisor_on_core(NULL);
            cur--;
        }
    }

    status = mp_services->SwitchBSP(mp_services,
                                    0,
                                    TRUE);

    bf_start_hypervisor_on_core(NULL);

    return EFI_SUCCESS;

fail:

    return status;

}


EFI_STATUS bf_start_by_interactive()
{
    Print(L"Interactive start\n");
    EFI_STATUS status;

    EFI_MP_SERVICES_PROTOCOL *mp_services;

    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&mp_services);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    UINTN ncpus = bf_num_cpus();
    if (ncpus == 0) {
        Print(L"bf_start_by_interactive: error bf_num_cpus returned zero\n");
        return EFI_NOT_FOUND;
    }

    UINTN started[16] = {0};

    EFI_INPUT_KEY pressed;
    while (1) {

        EFI_STATUS status = console_get_keystroke(&pressed);
        if (EFI_ERROR(status)) {
            PRINT_ERROR(status);
            goto fail;
        }

        if (pressed.ScanCode == 0) {
            if (pressed.UnicodeChar >= L'1' && pressed.UnicodeChar <= L'9') {
                UINTN core = (UINTN)(pressed.UnicodeChar - L'0');
                if (started[core] == 0) {
                    status = mp_services->StartupThisAP(mp_services,
                                                        (EFI_AP_PROCEDURE)bf_start_hypervisor_on_core,
                                                        core,
                                                        NULL,
                                                        50000000,
                                                        NULL,
                                                        NULL);
                    if (EFI_ERROR(status)) {
                        PRINT_ERROR(status);
                        goto fail;
                    }

                    started[core] = 1;
                }
                else {
                    status = mp_services->StartupThisAP(mp_services,
                                                        (EFI_AP_PROCEDURE)bf_cpuid_on_core,
                                                        core,
                                                        NULL,
                                                        50000000,
                                                        NULL,
                                                        NULL);
                    if (EFI_ERROR(status)) {
                        PRINT_ERROR(status);
                        goto fail;
                    }
                }
            }
            else if (pressed.UnicodeChar == L'0') {
                if (started[0] == 0) {
                    bf_start_hypervisor_on_core(NULL);
                    started[0] = 1;
                }
                else {
                    bf_cpuid_on_core(NULL);
                }
            }
        }
        else {
            break;
        }
    }

    Print(L"Leaving interactive mode\n");
    return EFI_SUCCESS;

fail:
    return status;

}
