
#include <efi.h>
#include <efilib.h>
#include "boot.h"

EFI_STATUS console_get_keystroke(EFI_INPUT_KEY *key)
{
    UINTN EventIndex;
    EFI_STATUS status;

    do {
        gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
        status = gST->ConIn->ReadKeyStroke(gST->ConIn, key);
    }
    while (status == EFI_NOT_READY);

    return status;
}

#define EFI_MODULE(name) \
    extern boot_ret_t register_module_##name(void);
#include "module.h"
#undef EFI_MODULE

void register_modules()
{
#define EFI_MODULE(name) \
    register_module_##name();
#include "module.h"
#undef EFI_MODULE
}

EFI_STATUS efi_main(EFI_HANDLE image_in, EFI_SYSTEM_TABLE *st_in)
{
    InitializeLib(image_in, st_in);

    Print(L"=======================================\n");
    Print(L" ___                __ _           _   \n");
    Print(L"| _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__\n");
    Print(L"| _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /\n");
    Print(L"|___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\\n");
    Print(L"     EFI Loader  \n");
    Print(L"=======================================\n");

    register_modules();
    boot_ret_t ret = boot_start();

    if (ret != BOOT_NOT_FOUND) {
        Print(L"boot_start returned %d\n", ret);
    }

    console_get_keystroke(NULL);

    return EFI_NOT_FOUND;
}
