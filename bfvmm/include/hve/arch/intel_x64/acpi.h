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
#include <cstring>
#include <mutex>

#include "vcpu.h"

namespace bfvmm::intel_x64 {

class acpi_table {
public:
    using map_t = bfvmm::x64::unique_map<uint8_t>;

    acpi_table(map_t &map, size_t len) :
        m_map{std::move(map)},
        m_len{len}
    {}

    operator bool() const
    { return m_map.get() != nullptr; }

    map_t::element_type *get() const
    { return m_map.get(); }

    uintptr_t size() const
    { return m_len; }

    void set_size(size_t size)
    { m_len = size; }

    void set_map(map_t &&map)
    { m_map = std::move(map); }

    acpi_table() = default;
    ~acpi_table() = default;

    acpi_table(const acpi_table &tab) = delete;
    acpi_table(acpi_table &&tab) = default;

    acpi_table &operator=(const acpi_table &tab) = delete;
    acpi_table &operator=(acpi_table &&tab) = default;

private:

    bfvmm::x64::unique_map<uint8_t> m_map{};
    size_t m_len{};
};

inline std::mutex g_acpi_mtx{};
inline acpi_table g_rsdp_tbl{};
inline acpi_table g_xsdt_tbl{};

// Map FADT (sig "FACP")
// Map FACS
// Print wake vector

#pragma pack(push, 1)

struct acpi_rsdp {
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

struct acpi_header {
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

#pragma pack(pop)

inline void map_rsdp(vcpu_t *vcpu, uintptr_t rsdp_gpa)
{
    if (g_rsdp_tbl) {
        return;
    }

    auto map = vcpu->map_gpa_4k<uint8_t>(rsdp_gpa);
    expects(strncmp(reinterpret_cast<const char *>(map.get()), "RSD PTR ", 8) == 0);

    auto tbl = reinterpret_cast<const acpi_rsdp *>(map.get());
    expects(tbl->rev == 2);

    g_rsdp_tbl.set_size(tbl->length);
    g_rsdp_tbl.set_map(std::move(map));

    ensures(g_rsdp_tbl);
}

inline void map_xsdt(vcpu_t *vcpu, uintptr_t rsdp_gpa)
{
    if (g_xsdt_tbl) {
        return;
    }

    if (!g_rsdp_tbl) {
        map_rsdp(vcpu, rsdp_gpa);
    }

    auto rsdp = reinterpret_cast<const acpi_rsdp *>(g_rsdp_tbl.get());
    auto xsdt_gpa = rsdp->xsdt_addr;
    auto xsdt_gpa_4k = bfn::upper(xsdt_gpa, 12);

    expects(xsdt_gpa_4k == bfn::upper(xsdt_gpa + sizeof(acpi_header) - 1, 12));
    uint64_t xsdt_len = 0;

    // TODO: Need to add unmap/release APIs
    {
        auto map = vcpu->map_gpa_4k<char>(xsdt_gpa, sizeof(acpi_header));
        expects(strncmp(map.get(), "XSDT", 4) == 0);

        auto hdr = reinterpret_cast<const acpi_header *>(map.get());
        expects(xsdt_gpa_4k == bfn::upper(xsdt_gpa + hdr->length - 1, 12));
        xsdt_len = hdr->length;
    }

    g_xsdt_tbl.set_size(xsdt_len);
    g_xsdt_tbl.set_map(vcpu->map_gpa_4k<uint8_t>(xsdt_gpa, xsdt_len));

    ensures(g_xsdt_tbl);
}
}

#endif
