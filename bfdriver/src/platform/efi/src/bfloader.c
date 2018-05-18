//#include <assert.h>

#include "bfefi.h"
#include "bflib.h"
#include "bfloader.h"
#include "common.h"

EFI_HANDLE this_image_h;
EFI_MP_SERVICES_PROTOCOL *g_mp_services;

extern char target_module_start[];
extern uint64_t target_module_size;

prestart_fn_t prestart_fns[NR_PRESTART_FNS];
start_fn_t start_fns[NR_START_FNS];
poststart_fn_t poststart_fns[NR_POSTSTART_FNS];

struct g_boot_data;

static void inline run_prestart_fns(struct boot_data *data)
{
    size_t i;
    for (i = 0U; i < NR_PRESTART_FNS; ++i) {
        prestart_fns[i](data);
    }
}

static void inline run_start_fns(struct boot_data *data)
{
    size_t i;
    for (i = 0U; i < NR_START_FNS; ++i) {
        start_fns[i](data);
    }
}

static void inline run_poststart_fns(struct boot_data *data)
{
    size_t i;
    for (i = 0U; i < NR_POSTSTART_FNS; ++i) {
        poststart_fns[i](data);
    }
}

static void inline init_boot_data(EFI_HANDLE img_in, EFI_SYTEM_TABLE *st_in)
{
    g_boot_data = {
        .this_image = hnd_in,
        .sys_table = st_in
    };
}

EFI_STATUS add_boot_prestart_fn(prestart_fn_t fn)
{
    static size_t nr_added = 0U;
    if (nr_added == NR_PRESTART_FNS) {
        Print(L"No room for another prestart function.\n");
        Print(L"Try increasing the NR_PRESTART_FNS compiler define\n");
        return EFI_NOT_FOUND;
    }

    prestart_fn[nr_added++] = fn;
}

EFI_STATUS add_boot_start_fn(start_fn_t fn)
{
    static size_t nr_added = 0U;
    if (nr_added == NR_START_FNS) {
        Print(L"No room for another start function.\n");
        Print(L"Try increasing the NR_START_FNS compiler define\n");
        return EFI_NOT_FOUND;
    }

    start_fn[nr_added++] = fn;
}

EFI_STATUS add_boot_poststart_fn(poststart_fn_t fn)
{
    static size_t nr_added = 0U;
    if (nr_added == NR_POSTSTART_FNS) {
        Print(L"No room for another poststart function.\n");
        Print(L"Try increasing the NR_POSTSTART_FNS compiler define\n");
        return EFI_NOT_FOUND;
    }

    poststart_fn[nr_added++] = fn;
}

EFI_STATUS efi_main(EFI_HANDLE image_in, EFI_SYSTEM_TABLE *st_in)
{
    init_boot_data(image_in, st_in);
    register_modules();

    run_prestart_fns(&g_boot_data);
    run_start_fns(&g_boot_data);
    run_poststart_fns(&g_boot_data);
}

EFI_STATUS default_prestart()
{
    EFI_HANDLE img = g_boot_data.this_handle;
    EFI_SYSTEM_TABLE *st = g_boot_data.sys_table;

    bf_init_lib(img, st);

    Print(L"=======================================\n");
    Print(L" ___                __ _           _   \n");
    Print(L"| _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__\n");
    Print(L"| _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /\n");
    Print(L"|___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\\n");
    Print(L"     EFI Loader  \n");
    Print(L"=======================================\n");

    EFI_STATUS status;

    EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID **)&g_mp_services);
    if (EFI_ERROR(status)) {
        PRINT_ERROR(status);
        goto fail;
    }

    Print(L"Adding hypervisor module..\n");
    int64_t ret = common_add_module((const char *)target_module_start,
                                    (uint64_t)target_module_size);
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

fail:
    console_get_keystroke(NULL);
    return EFI_ABORTED;
}

EFI_STATUS default_start()
{
    bf_start_by_startupallaps();
    return EFI_SUCCESS;
}

EFI_STATUS default_poststart()
{
    Print(L"Running base_poststart");

    // returning EFI_NOT_FOUND generally causes firmware to boot next
    // image in boot order without further prompting
    return EFI_NOT_FOUND;
}

void register_module()
{
    add_boot_prestart_fn(default_prestart);
    add_boot_start_fn(default_start);
    add_boot_poststart_fn(default_poststart);
}

/**
 * Top-level module registration
 */
void register_modules()
{
    // call register_module for each module

    return;
}
