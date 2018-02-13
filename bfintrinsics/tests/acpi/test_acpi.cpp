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

#include <catch/catch.hpp>
#include <intrinsics.h>

uint8_t g_rsdp[36] = {
    'R', 'S', 'D', ' ', 'P', 'T', 'R', ' ',     // Signature
    0,                                          // Checksum
    'O', 'E', 'M', ' ', 'I', 'D',               // OEM ID
    2,                                          // Revision
    0, 0, 0, 0,                                 // RSDT Address (Not a real address)
    36, 0, 0, 0,                                // Length
    0, 0, 0, 0,                                 // XSDT Address (Not a real address)
    0,                                          // Extended Checksum
    0, 0, 0                                     // Reserved
};

uint8_t g_xsdt[52] = {
    'X', 'S', 'D', 'T',                         // Signature
    44, 0, 0, 0,                                // Length
    1,                                          // Revision
    0,                                          // Checksum
    'O', 'E', 'M', ' ', 'I', 'D',               // OEM ID
    'O', 'E', 'M', ' ', 'X', 'S', 'D', 'T',     // OEM Table ID
    1, 0, 0, 0,                                 // OEM Revision
    'T', 'E', 'S', 'T',                         // Creator ID
    1, 0, 0, 0,                                 // Creator Revision
    1, 0, 0, 0, 0, 0, 0, 0                      // Entry 1 (Not a real address)
};

uint8_t g_rsdt[44] = {
    'R', 'S', 'D', 'T',                         // Signature
    40, 0, 0, 0,                                // Length
    1,                                          // Revision
    0,                                          // Checksum
    'O', 'E', 'M', ' ', 'I', 'D',               // OEM ID
    'O', 'E', 'M', ' ', 'R', 'S', 'D', 'T',     // OEM Table ID
    1, 0, 0, 0,                                 // OEM Revision
    'T', 'E', 'S', 'T',                         // Creator ID
    1, 0, 0, 0,                                 // Creator Revision
    1, 0, 0, 0                                  // Entry 1 (Not a real address)
};

uint8_t g_madt[84] = {
    'A', 'P', 'I', 'C',                         // Signature
    84, 0, 0, 0,                                // Length
    4,                                          // Revision
    0,                                          // Checksum
    'O', 'E', 'M', ' ', 'I', 'D',               // OEM ID
    'O', 'E', 'M', ' ', 'M', 'A', 'D', 'T',     // OEM Table ID
    1, 0, 0, 0,                                 // OEM Revision
    'T', 'E', 'S', 'T',                         // Creator ID
    1, 0, 0, 0,                                 // Creator Revision
    1, 0, 0, 0,                                 // Local Interrupt Address
    1, 0, 0, 0,                                 // Flags
    // Local APIC 1
    0,                                          // Type
    8,                                          // Length
    1,                                          // ACPI UID
    1,                                          // APIC ID
    1, 0, 0, 0,                                 // Flags
    // Local APIC 2
    0,                                          // Type
    8,                                          // Length
    2,                                          // ACPI UID
    2,                                          // APIC ID
    1, 0, 0, 0,                                 // Flags
    // IO APIC 1
    1,                                          // Type
    12,                                         // Length
    1,                                          // IO APIC ID
    0,                                          // Reserved
    1, 0, 0, 0,                                 // IO APIC Address
    1, 0, 0, 0,                                 // Global System Interrupt Base
    // IO Apic 2
    1,                                          // Type
    12,                                         // Length
    2,                                          // IO APIC ID
    0,                                          // Reserved
    2, 0, 0, 0,                                 // IO APIC Address
    1, 0, 0, 0                                  // Global System Interrupt Base
};

uint8_t g_lapic[8] = {
    0,                                          // Type
    8,                                          // Length
    1,                                          // ACPI UID
    1,                                          // APIC ID
    1, 0, 0, 0                                  // Flags
};

uint8_t g_ioapic[12] = {
    1,                                          // Type
    12,                                         // Length
    1,                                          // IO APIC ID
    0,                                          // Reserved
    1, 0, 0, 0,                                 // IO APIC Address
    1, 0, 0, 0                                  // Global System Interrupt Base
};

TEST_CASE("test name goes here")
{
    CHECK(true);
}

TEST_CASE("acpi read_uint32")
{
    uint8_t num[4] = { 8, 0, 0, 0 };
    CHECK(acpi::read_uint32(num) == 8);
}

TEST_CASE("acpi read_uint64")
{
    uint8_t num[8] = { 8, 0, 0, 0, 0, 0, 0, 0 };
    CHECK(acpi::read_uint64(num) == 8);
}

TEST_CASE("acpi rsdp: signature")
{
    namespace rsdp = acpi::rsdp;
    char sig[9] = { ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '\0' };

    uint8_t* sig_p = rsdp::signature(g_rsdp);
    memcpy(sig, sig_p, rsdp::signature_length);
    CHECK(strcmp(sig, "RSD PTR ") == 0);
}

TEST_CASE("acpi rsdp: checksum")
{
    namespace rsdp = acpi::rsdp;

    CHECK(rsdp::checksum(g_rsdp) == 0);
}

TEST_CASE("acpi rsdp: oem_id")
{
    namespace rsdp = acpi::rsdp;
    char id[7] = { ' ', ' ', ' ', ' ', ' ', ' ', '\0' };

    uint8_t* id_p = rsdp::oem_id(g_rsdp);
    memcpy(id, id_p, rsdp::oem_id_length);
    CHECK(strcmp(id, "OEM ID") == 0);
}

TEST_CASE("acpi rsdp: revision")
{
    namespace rsdp = acpi::rsdp;

    CHECK(rsdp::revision(g_rsdp) == 2);
}

TEST_CASE("acpi rsdp: rsdt_address")
{
    namespace rsdp = acpi::rsdp;

    CHECK(rsdp::rsdt_address(g_rsdp) == 0);
}

TEST_CASE("acpi rsdp: length")
{
    namespace rsdp = acpi::rsdp;

    CHECK(rsdp::length(g_rsdp) == 36);
}

TEST_CASE("acpi rsdp: xsdt_address")
{
    namespace rsdp = acpi::rsdp;

    CHECK(rsdp::xsdt_address(g_rsdp) == 0);
}

TEST_CASE("acpi rsdp: ext_checksum")
{
    namespace rsdp = acpi::rsdp;

    CHECK(rsdp::ext_checksum(g_rsdp) == 0);
}

TEST_CASE("acpi rsdt: signature")
{
    namespace rsdt = acpi::rsdt;
    char sig[5] = { ' ', ' ', ' ', ' ', '\0' };

    uint8_t* sig_p = rsdt::signature(g_rsdt);
    memcpy(sig, sig_p, rsdt::signature_length);
    CHECK(strcmp(sig, "RSDT") == 0);
}

TEST_CASE("acpi rsdt: length")
{
    namespace rsdt = acpi::rsdt;

    CHECK(rsdt::length(g_rsdt) == 40);
}

TEST_CASE("acpi rsdt: revision")
{
    namespace rsdt = acpi::rsdt;

    CHECK(rsdt::revision(g_rsdt) == 1);
}

TEST_CASE("acpi rsdt: checksum")
{
    namespace rsdt = acpi::rsdt;

    CHECK(rsdt::checksum(g_rsdt) == 0);
}

TEST_CASE("acpi rsdt: oem_id")
{
    namespace rsdt = acpi::rsdt;
    char id[7] = { ' ', ' ', ' ', ' ', ' ', ' ', '\0' };

    uint8_t* id_p = rsdt::oem_id(g_rsdt);
    memcpy(id, id_p, rsdt::oem_id_length);
    CHECK(strcmp(id, "OEM ID") == 0);
}

TEST_CASE("acpi rsdt: oem_table_id")
{
    namespace rsdt = acpi::rsdt;
    char table_id[9] = { ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '\0' };

    uint8_t* table_id_p = rsdt::oem_table_id(g_rsdt);
    memcpy(table_id, table_id_p, rsdt::oem_table_id_length);
    CHECK(strcmp(table_id, "OEM RSDT") == 0);
}

TEST_CASE("acpi rsdt: oem_revision")
{
    namespace rsdt = acpi::rsdt;

    CHECK(rsdt::oem_revision(g_rsdt) == 1);
}

TEST_CASE("acpi rsdt: creator_id")
{
    namespace rsdt = acpi::rsdt;
    char creator_id[5] = { ' ', ' ', ' ', ' ', '\0' };

    uint8_t* creator_id_p = rsdt::creator_id(g_rsdt);
    memcpy(creator_id, creator_id_p, rsdt::creator_id_length);
    CHECK(strcmp(creator_id, "TEST") == 0);
}

TEST_CASE("acpi rsdt: creator_revision")
{
    namespace rsdt = acpi::rsdt;

    CHECK(rsdt::creator_revision(g_rsdt) == 1);
}

TEST_CASE("acpi rsdt: entries")
{
    namespace rsdt = acpi::rsdt;

    CHECK(acpi::read_uint32(rsdt::entries(g_rsdt)) == 1);
}

TEST_CASE("acpi xsdt: signature")
{
    namespace xsdt = acpi::xsdt;
    char sig[5] = { ' ', ' ', ' ', ' ', '\0' };

    uint8_t* sig_p = xsdt::signature(g_xsdt);
    memcpy(sig, sig_p, xsdt::signature_length);
    CHECK(strcmp(sig, "XSDT") == 0);
}

TEST_CASE("acpi xsdt: length")
{
    namespace xsdt = acpi::xsdt;

    CHECK(xsdt::length(g_xsdt) == 44);
}

TEST_CASE("acpi xsdt: revision")
{
    namespace xsdt = acpi::xsdt;

    CHECK(xsdt::revision(g_xsdt) == 1);
}

TEST_CASE("acpi xsdt: checksum")
{
    namespace xsdt = acpi::xsdt;

    CHECK(xsdt::checksum(g_xsdt) == 0);
}

TEST_CASE("acpi xsdt: oem_id")
{
    namespace xsdt = acpi::xsdt;
    char id[7] = { ' ', ' ', ' ', ' ', ' ', ' ', '\0' };

    uint8_t* id_p = xsdt::oem_id(g_xsdt);
    memcpy(id, id_p, xsdt::oem_id_length);
    CHECK(strcmp(id, "OEM ID") == 0);
}

TEST_CASE("acpi xsdt: oem_table_id")
{
    namespace xsdt = acpi::xsdt;
    char table_id[9] = { ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '\0' };

    uint8_t* table_id_p = xsdt::oem_table_id(g_xsdt);
    memcpy(table_id, table_id_p, xsdt::oem_table_id_length);
    CHECK(strcmp(table_id, "OEM XSDT") == 0);
}

TEST_CASE("acpi xsdt: oem_revision")
{
    namespace xsdt = acpi::xsdt;

    CHECK(xsdt::oem_revision(g_xsdt) == 1);
}

TEST_CASE("acpi xsdt: creator_id")
{
    namespace xsdt = acpi::xsdt;
    char creator_id[5] = { ' ', ' ', ' ', ' ', '\0' };

    uint8_t* creator_id_p = xsdt::creator_id(g_xsdt);
    memcpy(creator_id, creator_id_p, xsdt::creator_id_length);
    CHECK(strcmp(creator_id, "TEST") == 0);
}

TEST_CASE("acpi xsdt: creator_revision")
{
    namespace xsdt = acpi::xsdt;

    CHECK(xsdt::creator_revision(g_xsdt) == 1);
}

TEST_CASE("acpi xsdt: entries")
{
    namespace xsdt = acpi::xsdt;

    CHECK(acpi::read_uint32(xsdt::entries(g_xsdt)) == 1);
}

TEST_CASE("acpi madt: signature")
{
    namespace madt = acpi::madt;
    char sig[5] = { ' ', ' ', ' ', ' ', '\0' };

    uint8_t* sig_p = madt::signature(g_madt);
    memcpy(sig, sig_p, madt::signature_length);
    CHECK(strcmp(sig, "APIC") == 0);
}

TEST_CASE("acpi madt: length")
{
    namespace madt = acpi::madt;

    CHECK(madt::length(g_madt) == 84);
}

TEST_CASE("acpi madt: revision")
{
    namespace madt = acpi::madt;

    CHECK(madt::revision(g_madt) == 4);
}

TEST_CASE("acpi madt: checksum")
{
    namespace madt = acpi::madt;

    CHECK(madt::checksum(g_madt) == 0);
}

TEST_CASE("acpi madt: oem_id")
{
    namespace madt = acpi::madt;
    char id[7] = { ' ', ' ', ' ', ' ', ' ', ' ', '\0' };

    uint8_t* id_p = madt::oem_id(g_madt);
    memcpy(id, id_p, madt::oem_id_length);
    CHECK(strcmp(id, "OEM ID") == 0);
}

TEST_CASE("acpi madt: oem_table_id")
{
    namespace madt = acpi::madt;
    char table_id[9] = { ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '\0' };

    uint8_t* table_id_p = madt::oem_table_id(g_madt);
    memcpy(table_id, table_id_p, madt::oem_table_id_length);
    CHECK(strcmp(table_id, "OEM MADT") == 0);
}

TEST_CASE("acpi madt: oem_revision")
{
    namespace madt = acpi::madt;

    CHECK(madt::oem_revision(g_madt) == 1);
}

TEST_CASE("acpi madt: creator_id")
{
    namespace madt = acpi::madt;
    char creator_id[5] = { ' ', ' ', ' ', ' ', '\0' };

    uint8_t* creator_id_p = madt::creator_id(g_madt);
    memcpy(creator_id, creator_id_p, madt::creator_id_length);
    CHECK(strcmp(creator_id, "TEST") == 0);
}

TEST_CASE("acpi madt: creator_revision")
{
    namespace madt = acpi::madt;

    CHECK(madt::creator_revision(g_madt) == 1);
}

TEST_CASE("acpi madt: local_interrupt_address")
{
    namespace madt = acpi::madt;

    CHECK(madt::local_interrupt_address(g_madt) == 1);
}

TEST_CASE("acpi madt: flags")
{
    namespace madt = acpi::madt;

    CHECK(madt::flags(g_madt) == 1);
}

TEST_CASE("acpi madt: ics")
{
    namespace madt = acpi::madt;

    CHECK(*(madt::ics(g_madt)) == 0);
}

TEST_CASE("acpi madt: is_pcat_compatible")
{
    namespace madt = acpi::madt;

    CHECK(madt::is_pcat_compatible(g_madt));
    g_madt[40] = 0;
    CHECK_FALSE(madt::is_pcat_compatible(g_madt));
}

TEST_CASE("acpi local_apic: type")
{
    namespace lapic = acpi::local_apic;

    CHECK(lapic::type(g_lapic) == 0);
}

TEST_CASE("acpi local_apic: length")
{
    namespace lapic = acpi::local_apic;

    CHECK(lapic::length(g_lapic) == 8);
}

TEST_CASE("acpi local_apic: acpi_uid")
{
    namespace lapic = acpi::local_apic;

    CHECK(lapic::acpi_uid(g_lapic) == 1);
}

TEST_CASE("acpi local_apic: acpi_id")
{
    namespace lapic = acpi::local_apic;

    CHECK(lapic::acpi_id(g_lapic) == 1);
}

TEST_CASE("acpi local_apic: flags")
{
    namespace lapic = acpi::local_apic;

    CHECK(lapic::flags(g_lapic) == 1);
}

TEST_CASE("acpi local_apic: is_enabled")
{
    namespace lapic = acpi::local_apic;

    CHECK(lapic::is_enabled(g_lapic));
    g_lapic[4] = 0;
    CHECK_FALSE(lapic::is_enabled(g_lapic));
}

TEST_CASE("acpi io_apic: type")
{
    namespace io_apic = acpi::io_apic;

    CHECK(io_apic::type(g_ioapic) == 1);
}

TEST_CASE("acpi io_apic: length")
{
    namespace io_apic = acpi::io_apic;

    CHECK(io_apic::length(g_ioapic) == 12);
}

TEST_CASE("acpi io_apic: io_apic_id")
{
    namespace io_apic = acpi::io_apic;

    CHECK(io_apic::io_apic_id(g_ioapic) == 1);
}

TEST_CASE("acpi io_apic: io_apic_address")
{
    namespace io_apic = acpi::io_apic;

    CHECK(io_apic::io_apic_address(g_ioapic) == 1);
}

TEST_CASE("acpi io_apic: global_interrupt_base")
{
    namespace io_apic = acpi::io_apic;

    CHECK(io_apic::global_interrupt_base(g_ioapic) == 1);
}
