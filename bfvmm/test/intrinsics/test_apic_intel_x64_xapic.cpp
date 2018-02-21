//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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
#include <intrinsics/x86/intel_x64.h>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

std::map<cpuid::field_type, cpuid::value_type> g_edx_cpuid;

struct cpuid_regs {
    cpuid::value_type edx;
};

extern "C" uint32_t
test_cpuid_edx(uint32_t val) noexcept
{ return g_edx_cpuid[val]; }

TEST_CASE("xapic_supported")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_edx_cpuid[cpuid::feature_information::addr] =
        cpuid::feature_information::edx::apic::mask;
    CHECK(xapic::supported());

    g_edx_cpuid[cpuid::feature_information::addr] = 0x0;
    CHECK_FALSE(xapic::supported());
}

#endif
