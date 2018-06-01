
#include "base.h"
#include "boot.h"
#include "mp_service.h"
#include "bfelf_loader.h"
#include "common.h"


EFI_MP_SERVICES_PROTOCOL *g_mp_services;
extern char target_vmm_start[];
extern char target_vmm_end[];


VOID __attribute__((ms_abi)) bf_start_hypervisor_on_core(VOID *data)
{
    (void)data;
    _set_ne();
    Print(L"Starting hypervisor on core.\n");
    platform_start_core();

    return;
}

boot_ret_t base_start_fn()
{
    EFI_STATUS status;

    uint64_t target_vmm_size = (uint64_t)(target_vmm_end - target_vmm_start);
    Print(L"target_vmm_size %x\n", target_vmm_size);

    int64_t ret = common_add_module((const char *)target_vmm_start,
                                    (uint64_t)target_vmm_size);
    if (ret < 0) {
        Print(L"common_add_module returned %a\n", ec_to_str(ret));
        goto fail;
    }

    Print(L"Loading modules..\n");
    ret = common_load_vmm();
    if (ret < 0) {
        Print(L"common_load_vmm returned %a\n", ec_to_str(ret));
        goto fail;
    }

    uint64_t cpus = platform_num_cpus();
    if (cpus == 0) {
        Print(L"Error: bf_start_by_startupallaps: bf_num_cpus\n");
        goto fail;
    }
    Print(L"Detected %d CPUs.\n", cpus);

    Print(L"Starting hypervisor...\n");
    if (cpus > 1) {
        status = g_mp_services->StartupAllAPs(g_mp_services,
                                              (EFI_AP_PROCEDURE)bf_start_hypervisor_on_core,
                                              TRUE,
                                              NULL,
                                              10000000,
                                              NULL,
                                              NULL);
        if (EFI_ERROR(status)) {
            Print(L"base_start_fn StartupAllAPs returned %r\n", status);
            goto fail;
        }
    }
    bf_start_hypervisor_on_core(NULL);

    return BOOT_CONTINUE;

fail:
    return BOOT_ABORT;
}

boot_ret_t base_prestart_fn()
{
    EFI_STATUS status;
    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&g_mp_services);
    if (EFI_ERROR(status)) {
        Print(L"Locate mpservicesprotocol error %r\n", status);
        return BOOT_ABORT;
    }
    return BOOT_CONTINUE;
}

boot_ret_t register_module_base()
{
    boot_add_prestart_fn(base_prestart_fn);
    boot_set_start_fn(base_start_fn);
    return BOOT_SUCCESS;
}
