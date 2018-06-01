
#include "boot.h"

static boot_fn_t _prestart_fns[NR_START_FNS] = {0};
static boot_fn_t _start_fn;
static boot_fn_t _poststart_fns[NR_START_FNS] = {0};

static boot_ret_t inline run_function_list(boot_fn_t fnlist[])
{
    uint64_t i;
    for (i = 0U; i < NR_START_FNS; ++i) {
        if (fnlist[i]) {
            boot_ret_t ret = fnlist[i]();
            if (ret == BOOT_INTERRUPT_STAGE) {
                return BOOT_CONTINUE;
            }
            else if (ret == BOOT_ABORT) {
                return ret;
            }

            if (ret != BOOT_CONTINUE) {
                return BOOT_ABORT;
            }
        }
        else {
            break;
        }
    }
    return BOOT_CONTINUE;
}

boot_ret_t boot_add_prestart_fn(boot_fn_t fn)
{
    static uint64_t nr_added = 0U;
    if (nr_added == NR_START_FNS) {
        return BOOT_FAIL;
    }

    _prestart_fns[nr_added++] = fn;
    return BOOT_SUCCESS;
}

boot_ret_t boot_set_start_fn(boot_fn_t fn)
{
    _start_fn = fn;
    return BOOT_SUCCESS;
}

boot_ret_t boot_add_poststart_fn(boot_fn_t fn)
{
    static uint64_t nr_added = 0U;
    if (nr_added == NR_START_FNS) {
        return BOOT_FAIL;
    }

    _poststart_fns[nr_added++] = fn;
    return BOOT_SUCCESS;
}

boot_ret_t boot_start()
{
    boot_ret_t ret = BOOT_CONTINUE;
    ret = run_function_list(_prestart_fns);
    if (ret != BOOT_CONTINUE) {
        return ret;
    }
    ret = _start_fn();
    if (ret != BOOT_CONTINUE) {
        return ret;
    }
    ret = run_function_list(_poststart_fns);
    if (ret != BOOT_CONTINUE) {
        return ret;
    }
    return BOOT_CONTINUE;
}
