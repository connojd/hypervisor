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

#ifndef INTRINSICS_LAPIC_INTEL_X64_H
#define INTRINSICS_LAPIC_INTEL_X64_H

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>
#include <arch/intel_x64/msrs.h>
#include <arch/intel_x64/cpuid.h>

#ifndef STATIC_INTRINSICS
#ifdef SHARED_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#else
#define EXPORT_INTRINSICS
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace intel_x64
{
namespace msrs
{

using value_type = ::x64::msrs::value_type;

namespace ia32_apic_base
{
    constexpr const auto addr = 0x0000001BU;
    constexpr const auto name = "ia32_apic_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace bsp
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "bsp";

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

    namespace extd
    {
        constexpr const auto mask = 0x0000000000000400ULL;
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

    namespace en
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "en";

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

    /* NOTE: `state` is a combination field of `extd` and `en` to facilitate
     * atomic apic state changes and provide a simplified interface */
    namespace state
    {
        constexpr const auto mask = 0xC00ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "state";

        constexpr const auto disabled = 0x0ULL;
        constexpr const auto invalid = 0x1ULL;
        constexpr const auto xapic = 0x2ULL;
        constexpr const auto x2apic = 0x3ULL;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void enable_x2apic() noexcept
        { set(x2apic); }

        inline auto enable_x2apic(value_type msr) noexcept
        { return set_bits(msr, mask, x2apic << from); }

        inline void enable_xapic() noexcept
        { set(xapic); }

        inline auto enable_xapic(value_type msr) noexcept
        { return set_bits(msr, mask, xapic << from); }

        inline void disable() noexcept
        { set(disabled); }

        inline auto disable(value_type msr) noexcept
        { return set_bits(msr, mask, disabled << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case x2apic:
                    bfdebug_subtext(level, name, "x2apic", msg);
                    return;
                case xapic:
                    bfdebug_subtext(level, name, "xapic", msg);
                    return;
                case disabled:
                    bfdebug_subtext(level, name, "disabled", msg);
                    return;
                case invalid:
                    bfdebug_subtext(level, name, "invalid", msg);
                    return;
            }
        }
    }

    namespace apic_base
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "apic_base";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask); }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask); }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        bsp::dump(level, msg);
        extd::dump(level, msg);
        en::dump(level, msg);
        apic_base::dump(level, msg);
    }
}
}

namespace lapic
{
    struct reg_info {
        uint32_t offset;
        bool readable;
        bool writeable;

        reg_info(const uint32_t& off)
            : offset(off) {}
        reg_info(const uint32_t& off, const bool& r, const bool& w)
            : offset(off), readable(r), writeable(w) {}

        bool operator<(const reg_info& rhs) const
        { return offset < rhs.offset; }

        bool operator==(const reg_info& rhs) const
        { return offset == rhs.offset; }
    };

    using addr_type = const ::x64::msrs::field_type;
    using size_type = const std::size_t;

    addr_type msr_start_reg = 0x800U;
    addr_type msr_end_reg = 0xBFFU;
    size_type msr_total_regs = (msr_end_reg - msr_start_reg) + 1U;

    inline auto is_present() noexcept
    {
        return ::intel_x64::cpuid::feature_information::edx::apic::is_enabled();
    }
}
}

#endif
