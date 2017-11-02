//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef APIC_INTEL_X64_H
#define APIC_INTEL_X64_H

#include <intrinsics/x86/intel/cpuid_intel_x64.h>
#include <intrinsics/x86/intel/msrs_intel_x64.h>

using namespace intel_x64;

// *INDENT-OFF*

namespace intel_x64
{
namespace msrs
{

namespace ia32_apic_base
{
    constexpr const auto addr = 0x0000001BU;
    constexpr const auto name = "ia32_apic_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace extd
    {
        constexpr const auto mask = 0x00000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "extd";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace state
    {
        constexpr const auto mask = 0xC00ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "state";

        constexpr const auto disabled = 0x0ULL;
        constexpr const auto invalid = 0x4ULL;
        constexpr const auto xapic = 0x8ULL;
        constexpr const auto x2apic = 0xCULL;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline auto enable_x2apic_mode() noexcept
        { set(x2apic); }

        inline auto enable_x2apic_mode(value_type msr) noexcept
        { set(msr, x2apic); }

        inline auto enable_xapic_mode() noexcept
        { set(xapic); }

        inline auto enable_xapic_mode() noexcept
        { set(msr, xapic); }

        inline auto disable() noexcept
        { set(disable); }

        inline auto disable() noexcept
        { set(msr, disable); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        extd::dump(level, msg);
        state::dump(level, msg);
    }
}

namespace lapic
{
    inline auto present() noexcept
    {
        return cpuid::feature_information::edx::apic::is_enabled();
    }

    inline auto x2apic_supported() noexcept
    {
        return cpuid::feature_information::ecx::x2apic::is_enabled();
    }
}
}

// *INDENT-ON*

#endif
