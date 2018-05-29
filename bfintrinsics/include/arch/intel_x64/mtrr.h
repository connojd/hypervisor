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

#ifndef MTRR_INTEL_X64_H
#define MTRR_INTEL_X64_H

#include "msrs.h"
#include "cpuid.h"

// *INDENT-OFF*

namespace intel_x64
{
namespace mtrr
{

using value_type = ::intel_x64::msrs::value_type;

constexpr const auto uncacheable = 0x00ULL;
constexpr const auto write_combining = 0x01ULL;
constexpr const auto write_through = 0x04ULL;
constexpr const auto write_protected = 0x05ULL;
constexpr const auto write_back = 0x06ULL;

constexpr const auto uncacheable_mask = 1ULL << uncacheable;
constexpr const auto write_combining_mask = 1ULL << write_combining;
constexpr const auto write_through_mask = 1ULL << write_through;
constexpr const auto write_protected_mask = 1ULL << write_protected;
constexpr const auto write_back_mask = 1ULL << write_back;

constexpr const auto valid_type_mask = uncacheable_mask |
    write_combining_mask | write_through_mask |
    write_protected_mask | write_back_mask;

inline const char *type_to_str(uint64_t type)
{
    switch (type) {
        case uncacheable: return "uncacheable";
        case write_combining: return "write_combining";
        case write_through: return "write_through";
        case write_protected: return "write_protected";
        case write_back: return "write_back";
        default: return "invalid";
    }
}

inline bool is_supported()
{ return cpuid::feature_information::edx::mtrr::is_enabled(); }

namespace ia32_mtrrcap
{
    constexpr const auto addr = 0x000000FEU;
    constexpr const auto name = "ia32_mtrrcap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace vcnt
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vcnt";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace fixed_support
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "fixed_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace wc_support
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "wc_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace smrr_support
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "smrr_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        vcnt::dump(level, msg);
        fixed_support::dump(level, msg);
        wc_support::dump(level, msg);
        smrr_support::dump(level, msg);
    }
}

namespace ia32_mtrr_def_type
{
    constexpr const auto addr = 0x000002FFU;
    constexpr const auto name = "ia32_mtrr_def_type";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace type
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace fe
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "fe";

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

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace e
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "e";

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

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        fe::dump(level, msg);
        e::dump(level, msg);
    }
}

namespace physbase
{
    constexpr const auto start_addr = 0x00000200U;

    namespace type
    {
        constexpr const uint64_t mask = 0x00000000000000FFULL;
        constexpr const uint64_t from = 0ULL;
        constexpr const auto name = "type";

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline auto set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, value_type msr, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(msr), msg); }
    }

    /// The 'mask' variable of this namespace depends on the physical address
    /// size (pas) returned by cpuid.
    namespace physbase
    {
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto mask(value_type pas) noexcept
        { return ((1ULL << pas) - 1U) & ~(0x1000ULL - 1U); }

        inline auto get(value_type msr, value_type pas) noexcept
        { return get_bits(msr, mask(pas)) >> from; }

        inline auto set(value_type &msr, value_type val, value_type pas) noexcept
        { msr = set_bits(msr, mask(pas), val << from); }

        inline void dump(int level, value_type msr, value_type pas, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(msr, pas), msg); }
    }

    inline void dump(int level, value_type msr, value_type pas, std::string *msg = nullptr)
    {
        type::dump(level, msr, msg);
        physbase::dump(level, msr, pas, msg);
    }
}

namespace physmask
{
    constexpr const auto start_addr = 0x00000201U;

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline auto disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, value_type msr, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(msr), msg); }

    }

    /// The 'mask' variable of this namespace depends on the physical address
    /// size (pas) returned by cpuid.
    namespace physmask
    {
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto mask(value_type pas) noexcept
        { return ((1ULL << pas) - 1U) & ~(0x1000ULL - 1U); }

        inline auto get(value_type msr, value_type pas) noexcept
        { return get_bits(msr, mask(pas)) >> from; }

        inline auto set(value_type &msr, value_type val, value_type pas) noexcept
        { msr = set_bits(msr, mask(pas), val << from); }

        inline void dump(int level, value_type msr, value_type pas, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(msr, pas), msg); }
    }

    inline void dump(int level, value_type msr, value_type pas, std::string *msg = nullptr)
    {
        valid::dump(level, msr, msg);
        physmask::dump(level, msr, pas, msg);
    }
}

namespace fix64k_00000
{
    constexpr const auto addr = 0x00000250U;
    constexpr const auto name = "fix64k_00000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix16k_80000
{
    constexpr const auto addr = 0x00000258U;
    constexpr const auto name = "fix16k_80000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix16k_A0000
{
    constexpr const auto addr = 0x00000259U;
    constexpr const auto name = "fix16k_A0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_C0000
{
    constexpr const auto addr = 0x00000268U;
    constexpr const auto name = "fix4k_C0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_C8000
{
    constexpr const auto addr = 0x00000269U;
    constexpr const auto name = "fix4k_C8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_D0000
{
    constexpr const auto addr = 0x0000026AU;
    constexpr const auto name = "fix4k_D0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_D8000
{
    constexpr const auto addr = 0x0000026BU;
    constexpr const auto name = "fix4k_D8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_E0000
{
    constexpr const auto addr = 0x0000026CU;
    constexpr const auto name = "fix4k_E0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_E8000
{
    constexpr const auto addr = 0x0000026DU;
    constexpr const auto name = "fix4k_E8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_F0000
{
    constexpr const auto addr = 0x0000026EU;
    constexpr const auto name = "fix4k_F0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_F8000
{
    constexpr const auto addr = 0x0000026FU;
    constexpr const auto name = "fix4k_F8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

inline bool valid_mem_type(uint64_t type)
{
    switch (type) {
        case uncacheable:
        case write_combining:
        case write_through:
        case write_protected:
        case write_back:
            return true;
        default:
            return false;
    }
}

struct variable_range
{
    /// The minimum size required of a variable MTRR range.
    static constexpr uint64_t min_size = 0x1000U;

    /// size_to_mask
    ///
    /// @param pas the number of bits in a physical address
    /// @return the mask that determines the set of addresses that
    ///         lie in the range
    ///
    static uint64_t size_to_mask(uint64_t size, uint64_t pas);

    /// mask_to_size
    ///
    /// @param pas the number of bits in a physical address
    /// @return the size of the range
    ///
    static uint64_t mask_to_size(uint64_t mask, uint64_t pas);

    /// Constructor
    ///
    /// Create a variable MTRR range. The range has @param type memory type. Note
    /// that the @param mask must be chosen so that for any address addr, the
    /// following equation holds
    ///
    ///     (base & mask) == (base & addr)
    ///
    /// if and only if addr is in the range being constructed.
    ///
    /// @param base the base address of the range
    /// @param mask the mask of the range
    /// @param type the memory type of the range
    /// @param pas the number of bits in a physical address
    ///
    explicit variable_range(
        uintptr_t base, uint64_t mask, uint64_t type, uint64_t pas)
    {
        expects(valid_mem_type(type));
        expects(pas >= 36U && pas <= 52U);
        expects(x64::is_physical_address_valid(base, pas));

        auto size = variable_range::mask_to_size(mask, pas);

        expects(size >= min_size);
        expects(base >= size);
        expects((size & (size - 1U)) == 0U);
        expects((base & (base - 1U)) == 0U);
        expects((base + size) > base);

        m_base = base;
        m_mask = mask;
        m_size = size;
        m_type = type;
    }

    /// contains
    ///
    /// @param addr the address to check
    /// @return true iff the range contains the given address
    ///
    bool contains(uintptr_t addr) const
    { return (m_mask & m_base) == (m_mask & addr); }

    /// @return the base address
    uintptr_t base() const
    { return m_base; }

    /// @return the size of the range
    uintptr_t size() const
    { return m_size; }

    /// @return the mask of the range
    uintptr_t mask() const
    { return m_mask; }

    /// @return the memory type of the range
    uint64_t type() const
    { return m_type; }

private:

    uintptr_t m_base;
    uint64_t m_size;
    uint64_t m_mask;
    uint64_t m_type;

public:

    /// @cond

    variable_range() noexcept = delete;

    variable_range(variable_range &&) noexcept = default;
    variable_range &operator=(variable_range &&) noexcept = default;

    variable_range(const variable_range &) = delete;
    variable_range &operator=(const variable_range &) = delete;

    /// @endcond
};

inline uint64_t variable_range::size_to_mask(uint64_t size, uint64_t pas)
{
    const uint64_t bits = (0x1ULL << pas) - 1U;
    return ~(size - 1U) & bits;
}

inline uint64_t variable_range::mask_to_size(uint64_t mask, uint64_t pas)
{
    const uint64_t bits = (0x1ULL << pas) - 1U;
    return (~mask & bits) + 1U;
}

}
}

// *INDENT-ON*

#endif
