//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA


#ifndef ACPI_INTEL_X64_H
#define ACPI_INTEL_X64_H

// *INDENT-OFF*

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_INTRINSICS
#ifdef SHARED_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#else
#define EXPORT_INTRINSICS
#endif

namespace acpi
{

using acpi_ptr = uint8_t*;

inline uint32_t read_uint32(acpi_ptr p)
{
    uint32_t ret = 0;
    ret |= gsl::narrow_cast<uint32_t>(p[0]);
    ret |= gsl::narrow_cast<uint32_t>(p[1]) << 8;
    ret |= gsl::narrow_cast<uint32_t>(p[2]) << 16;
    ret |= gsl::narrow_cast<uint32_t>(p[3]) << 24;
    return ret;
}

inline uint64_t read_uint64(acpi_ptr p)
{
    uint64_t ret = 0;
    ret |= gsl::narrow_cast<uint64_t>(p[0]);
    ret |= gsl::narrow_cast<uint64_t>(p[1]) << 8;
    ret |= gsl::narrow_cast<uint64_t>(p[2]) << 16;
    ret |= gsl::narrow_cast<uint64_t>(p[3]) << 24;
    ret |= gsl::narrow_cast<uint64_t>(p[4]) << 32;
    ret |= gsl::narrow_cast<uint64_t>(p[5]) << 40;
    ret |= gsl::narrow_cast<uint64_t>(p[6]) << 48;
    ret |= gsl::narrow_cast<uint64_t>(p[7]) << 56;
    return ret;
}

// Root System Description Pointer
namespace rsdp
{
    constexpr const auto signature_length = 8;
    constexpr const auto oem_id_length = 6;

    inline uint8_t* signature(acpi_ptr rsdp_p)
    { return rsdp_p; }

    inline uint8_t checksum(acpi_ptr rsdp_p)
    { return rsdp_p[8]; }

    inline uint8_t* oem_id(acpi_ptr rsdp_p)
    { return rsdp_p + 9; }

    inline uint8_t revision(acpi_ptr rsdp_p)
    { return rsdp_p[15]; }

    inline uint32_t rsdt_address(acpi_ptr rsdp_p)
    { return read_uint32(rsdp_p + 16); }

    inline uint32_t length(acpi_ptr rsdp_p)
    { return read_uint32(rsdp_p + 20); }

    inline uint64_t xsdt_address(acpi_ptr rsdp_p)
    { return read_uint64(rsdp_p + 24); }

    inline uint8_t ext_checksum(acpi_ptr rsdp_p)
    { return rsdp_p[32]; }
}

// Root System Description Table
namespace rsdt
{
    constexpr const auto signature_length = 4;
    constexpr const auto oem_id_length = 6;
    constexpr const auto oem_table_id_length = 8;
    constexpr const auto creator_id_length = 4;

    inline uint8_t* signature(acpi_ptr rsdt_p)
    { return rsdt_p; }

    inline uint32_t length(acpi_ptr rsdt_p)
    { return read_uint32(rsdt_p + 4); }

    inline uint8_t revision(acpi_ptr rsdt_p)
    { return rsdt_p[8]; }

    inline uint8_t checksum(acpi_ptr rsdt_p)
    { return rsdt_p[9]; }

    inline uint8_t* oem_id(acpi_ptr rsdt_p)
    { return (rsdt_p + 10); }

    inline uint8_t* oem_table_id(acpi_ptr rsdt_p)
    { return (rsdt_p + 16); }

    inline uint32_t oem_revision(acpi_ptr rsdt_p)
    { return read_uint32(rsdt_p + 24); }

    inline uint8_t* creator_id(acpi_ptr rsdt_p)
    { return (rsdt_p + 28); }

    inline uint32_t creator_revision(acpi_ptr rsdt_p)
    { return read_uint32(rsdt_p + 32); }

    inline uint8_t* entries(acpi_ptr rsdt_p)
    { return (rsdt_p + 36); }
}

// Extended System Description Table
namespace xsdt
{
    constexpr const auto signature_length = 4;
    constexpr const auto oem_id_length = 6;
    constexpr const auto oem_table_id_length = 8;
    constexpr const auto creator_id_length = 4;

    inline uint8_t* signature(acpi_ptr xsdt_p)
    { return xsdt_p; }

    inline uint32_t length(acpi_ptr xsdt_p)
    { return read_uint32(xsdt_p + 4); }

    inline uint8_t revision(acpi_ptr xsdt_p)
    { return xsdt_p[8]; }

    inline uint8_t checksum(acpi_ptr xsdt_p)
    { return xsdt_p[9]; }

    inline uint8_t* oem_id(acpi_ptr xsdt_p)
    { return (xsdt_p + 10); }

    inline uint8_t* oem_table_id(acpi_ptr xsdt_p)
    { return (xsdt_p + 16); }

    inline uint32_t oem_revision(acpi_ptr xsdt_p)
    { return read_uint32(xsdt_p + 24); }

    inline uint8_t* creator_id(acpi_ptr xsdt_p)
    { return (xsdt_p + 28); }

    inline uint32_t creator_revision(acpi_ptr xsdt_p)
    { return read_uint32(xsdt_p + 32); }

    inline uint8_t* entries(acpi_ptr xsdt_p)
    { return (xsdt_p + 36); }
}

// Multiple APIC Description Table
namespace madt
{
    constexpr const auto signature_length = 4;
    constexpr const auto oem_id_length = 6;
    constexpr const auto oem_table_id_length = 8;
    constexpr const auto creator_id_length = 4;

    enum ics_type : uint32_t {
        LAPIC,
        IOAPIC,
        INTERRUPT_SOURCE_OVERRIDE,
        NMI,
        LAPIC_NMI,
        LAPIC_ADDRESS_OVERRIDE,
        IOSAPIC,
        LSAPIC,
        PLATFORM_INTERRUPT_SOURCES,
        X2_LAPIC_NMI,
        GICC,
        GICD,
        GIC_MSI_FRAME,
        GICR,
        GIC_ITS
    };

    inline uint8_t* signature(acpi_ptr madt_p)
    { return madt_p; }

    inline uint32_t length(acpi_ptr madt_p)
    { return read_uint32(madt_p + 4); }

    inline uint8_t revision(acpi_ptr madt_p)
    { return madt_p[8]; }

    inline uint8_t checksum(acpi_ptr madt_p)
    { return madt_p[9]; }

    inline uint8_t* oem_id(acpi_ptr madt_p)
    { return (madt_p + 10); }

    inline uint8_t* oem_table_id(acpi_ptr madt_p)
    { return (madt_p + 16); }

    inline uint32_t oem_revision(acpi_ptr madt_p)
    { return read_uint32(madt_p + 24); }

    inline uint8_t* creator_id(acpi_ptr madt_p)
    { return (madt_p + 28); }

    inline uint32_t creator_revision(acpi_ptr madt_p)
    { return read_uint32(madt_p + 32); }

    inline uint32_t local_interrupt_address(acpi_ptr madt_p)
    { return read_uint32(madt_p + 36); }

    inline uint32_t flags(acpi_ptr madt_p)
    { return read_uint32(madt_p + 40); }

    inline uint8_t* ics(acpi_ptr madt_p)
    { return (madt_p + 44); }

    inline bool is_pcat_compatible(acpi_ptr madt_p)
    { return flags(madt_p) & 0x1U; }
}

namespace local_apic
{
    inline uint8_t type(acpi_ptr lapic_p)
    { return lapic_p[0]; }

    inline uint8_t length(acpi_ptr lapic_p)
    { return lapic_p[1]; }

    inline uint8_t acpi_uid(acpi_ptr lapic_p)
    { return lapic_p[2]; }

    inline uint8_t acpi_id(acpi_ptr lapic_p)
    { return lapic_p[3]; }

    inline uint32_t flags(acpi_ptr lapic_p)
    { return read_uint32(lapic_p + 4); }

    inline bool is_enabled(acpi_ptr lapic_p)
    { return flags(lapic_p) & 0x1U; }
}

namespace io_apic
{
    inline uint8_t type(acpi_ptr ioapic_p)
    { return ioapic_p[0]; }

    inline uint8_t length(acpi_ptr ioapic_p)
    { return ioapic_p[1]; }

    inline uint8_t io_apic_id(acpi_ptr ioapic_p)
    { return ioapic_p[2]; }

    inline uint32_t io_apic_address(acpi_ptr ioapic_p)
    { return read_uint32(ioapic_p + 4); }

    inline uint32_t global_interrupt_base(acpi_ptr ioapic_p)
    { return read_uint32(ioapic_p + 8); }
}

}

// *INDENT-ON*

#endif // ACPI_INTEL_X64_H
