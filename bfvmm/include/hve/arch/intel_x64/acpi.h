//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef BFVMM_ACPI_X64_H
#define BFVMM_ACPI_X64_H

#include <bfgsl.h>
#include <bftypes.h>
#include "vcpu.h"

namespace acpi {

#pragma pack(push, 1)

struct rsdp {
    uint8_t sig[8];
    uint8_t cksum;
    uint8_t oemid[6];
    uint8_t rev;
    uint32_t rsdt_addr;
    uint32_t length;
    uint64_t xsdt_addr;
    uint8_t ext_cksum;
    uint8_t rsvd[3];
};

struct header {
    uint8_t sig[4];
    uint32_t length;
    uint8_t rev;
    uint8_t cksum;
    uint8_t oem_id[6];
    uint8_t oem_tbl_id[8];
    uint32_t oem_rev;
    uint32_t creator_id;
    uint32_t creator_rev;
};

struct xsdt {
    struct header hdr;
};

inline auto map_rsdp(vcpu_t *vcpu, uintptr_t rsdp_gpa)
{
    auto map = vcpu->map_gpa_4k<const char>(rsdp_gpa);
    expects(strncmp(map.get(), "RSD PTR ", 8) == 0);

    auto tbl = reinterpret_cast<const rsdp *>(map.get());
    expects(tbl->rev == 2);

    return map;
}

inline auto map_xsdt(vcpu_t *vcpu, uintptr_t rsdp_gpa)
{
    auto rsdp_map = map_rsdp(vcpu, rsdp_gpa);
    auto xsdt_gpa = reinterpret_cast<const rsdp *>(rsdp_map.get())->xsdt_addr;
    auto xsdt_gpa_4k = bfn::upper(xsdt_gpa, 12);

    expects(xsdt_gpa_4k == bfn::upper(xsdt_gpa + sizeof(header) - 1, 12));
    uint64_t xsdt_len = 0;

    // TODO: Need to add unmap/release APIs
    {
        auto map = vcpu->map_gpa_4k<const char>(xsdt_gpa, sizeof(header));
        expects(strncmp(map.get(), "XSDT", 4) == 0);

        auto hdr = reinterpret_cast<const header *>(map.get());
        expects(xsdt_gpa_4k == bfn::upper(xsdt_gpa + hdr->length - 1, 12));
        xsdt_len = hdr->length;
    }

    return vcpu->map_gpa_4k<const char>(xsdt_gpa, len)
}

#pragma pack(pop)

}
