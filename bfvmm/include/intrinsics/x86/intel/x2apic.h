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

#ifndef X2APIC_INTEL_X64_H
#define X2APIC_INTEL_X64_H

#include <intrinsics/x86/common/msrs_x64.h>
#include <intrinsics/x86/intel/msrs_intel_x64.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace x2apic
{

using addr_type = x64::msrs::field_type;
using value_type = x64::msrs::value_type;
using vector_type = uint64_t;

constexpr const addr_type start_addr = 0x00000800U;
constexpr const addr_type end_addr = 0x00000BFFU;

//
// x2apic msrs
//
namespace apicid
{
    constexpr const auto addr = 0x00000802U;
    constexpr const auto name = "apicid";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace version
{
    constexpr const auto addr = 0x00000803U;
    constexpr const auto name = "version";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tpr
{
    constexpr const auto addr = 0x00000808U;
    constexpr const auto name = "tpr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ppr
{
    constexpr const auto addr = 0x0000080AU;
    constexpr const auto name = "ppr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace eoi
{
    constexpr const auto addr = 0x0000080BU;
    constexpr const auto name = "eoi";

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }
}

namespace ldr
{
    constexpr const auto addr = 0x0000080DU;
    constexpr const auto name = "ldr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace sivr
{
    constexpr const auto addr = 0x0000080FU;
    constexpr const auto name = "sivr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace apic_enable_bit
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "apic_enable_bit";

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

    namespace focus_checking
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "focus_checking";

        inline auto is_disabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_enabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void disable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return set_bit(msr, from); }

        inline void enable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace suppress_eoi_broadcast
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "suppress_eoi_broadcast";

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

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        vector::dump(level, msg);
        apic_enable_bit::dump(level, msg);
        focus_checking::dump(level, msg);
        suppress_eoi_broadcast::dump(level, msg);
    }
}

namespace isr0
{
    constexpr const auto addr = 0x00000810U;
    constexpr const auto name = "isr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace isr1
{
    constexpr const auto addr = 0x00000811U;
    constexpr const auto name = "isr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace isr2
{
    constexpr const auto addr = 0x00000812U;
    constexpr const auto name = "isr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace isr3
{
    constexpr const auto addr = 0x00000813U;
    constexpr const auto name = "isr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace isr4
{
    constexpr const auto addr = 0x00000814U;
    constexpr const auto name = "isr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace isr5
{
    constexpr const auto addr = 0x00000815U;
    constexpr const auto name = "isr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace isr6
{
    constexpr const auto addr = 0x00000816U;
    constexpr const auto name = "isr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace isr7
{
    constexpr const auto addr = 0x00000817U;
    constexpr const auto name = "isr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tmr0
{
    constexpr const auto addr = 0x00000818U;
    constexpr const auto name = "tmr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tmr1
{
    constexpr const auto addr = 0x00000819U;
    constexpr const auto name = "tmr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tmr2
{
    constexpr const auto addr = 0x0000081AU;
    constexpr const auto name = "tmr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tmr3
{
    constexpr const auto addr = 0x0000081BU;
    constexpr const auto name = "tmr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tmr4
{
    constexpr const auto addr = 0x0000081CU;
    constexpr const auto name = "tmr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tmr5
{
    constexpr const auto addr = 0x0000081DU;
    constexpr const auto name = "tmr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tmr6
{
    constexpr const auto addr = 0x0000081EU;
    constexpr const auto name = "tmr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace tmr7
{
    constexpr const auto addr = 0x0000081FU;
    constexpr const auto name = "tmr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace irr0
{
    constexpr const auto addr = 0x00000820U;
    constexpr const auto name = "irr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace irr1
{
    constexpr const auto addr = 0x00000821U;
    constexpr const auto name = "irr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace irr2
{
    constexpr const auto addr = 0x00000822U;
    constexpr const auto name = "irr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace irr3
{
    constexpr const auto addr = 0x00000823U;
    constexpr const auto name = "irr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace irr4
{
    constexpr const auto addr = 0x00000824U;
    constexpr const auto name = "irr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace irr5
{
    constexpr const auto addr = 0x00000825U;
    constexpr const auto name = "irr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace irr6
{
    constexpr const auto addr = 0x00000826U;
    constexpr const auto name = "irr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace irr7
{
    constexpr const auto addr = 0x00000827U;
    constexpr const auto name = "irr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace esr
{
    constexpr const auto addr = 0x00000828U;
    constexpr const auto name = "esr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace lvt_cmci
{
    constexpr const auto addr = 0x0000082FU;
    constexpr const auto name = "lvt_cmci";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_mode::dump(level, msg);
        delivery_status::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace icr
{
    constexpr const auto addr = 0x00000830U;
    constexpr const auto name = "icr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace lvt_timer
{
    constexpr const auto addr = 0x00000832U;
    constexpr const auto name = "lvt_timer";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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

    namespace timer_mode
    {
        constexpr const auto mask = 0x0000000000060000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "timer_mode";

        constexpr const auto one_shot = 0U;
        constexpr const auto periodic = 1U;
        constexpr const auto tsc_deadline = 2U;

        inline auto get()
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr)
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val)
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val)
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case one_shot: bfdebug_subtext(level, name, "one-shot", msg); break;
                case periodic: bfdebug_subtext(level, name, "periodic", msg); break;
                case tsc_deadline: bfdebug_subtext(level, name, "TSC-deadline", msg); break;
                default: bferror_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        vector::dump(level, msg);
        delivery_status::dump(level, msg);
        mask_bit::dump(level, msg);
        timer_mode::dump(level, msg);
    }
}

namespace lvt_thermal
{
    constexpr const auto addr = 0x00000833U;
    constexpr const auto name = "lvt_thermal";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_mode::dump(level, msg);
        delivery_status::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace lvt_pmi
{
    constexpr const auto addr = 0x00000834U;
    constexpr const auto name = "lvt_pmi";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_mode::dump(level, msg);
        delivery_status::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace lvt_lint0
{
    constexpr const auto addr = 0x00000835U;
    constexpr const auto name = "lvt_lint0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    namespace polarity
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "polarity";

        constexpr const auto active_high = 0U;
        constexpr const auto active_low = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case active_high: bfdebug_subtext(level, name, "active_high", msg); break;
                case active_low: bfdebug_subtext(level, name, "active_low", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    namespace remote_irr
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "remote_irr";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace trigger_mode
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "trigger_mode";

        constexpr const auto edge = 0U;
        constexpr const auto level = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int lev, std::string *msg = nullptr)
        {
            switch (get()) {
                case edge: bfdebug_subtext(lev, name, "edge", msg); break;
                case level: bfdebug_subtext(lev, name, "level", msg); break;
                default: bferror_subtext(lev, name, "INVALID", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_status::dump(level, msg);
        polarity::dump(level, msg);
        remote_irr::dump(level, msg);
        trigger_mode::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace lvt_lint1
{
    constexpr const auto addr = 0x00000836U;
    constexpr const auto name = "lvt_lint1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    namespace polarity
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "polarity";

        constexpr const auto active_high = 0U;
        constexpr const auto active_low = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case active_high: bfdebug_subtext(level, name, "active_high", msg); break;
                case active_low: bfdebug_subtext(level, name, "active_low", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    namespace remote_irr
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "remote_irr";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace trigger_mode
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "trigger_mode";

        constexpr const auto edge = 0U;
        constexpr const auto level = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int lev, std::string *msg = nullptr)
        {
            switch (get()) {
                case edge: bfdebug_subtext(lev, name, "edge", msg); break;
                case level: bfdebug_subtext(lev, name, "level", msg); break;
                default: bferror_subtext(lev, name, "INVALID", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_status::dump(level, msg);
        polarity::dump(level, msg);
        remote_irr::dump(level, msg);
        trigger_mode::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace lvt_error
{
    constexpr const auto addr = 0x00000837U;
    constexpr const auto name = "lvt_error";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
                default: bferror_subtext(level, name, "INVALID", msg); break;
            }
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_status::dump(level, msg);
    }
}

namespace init_count
{
    constexpr const auto addr = 0x00000838U;
    constexpr const auto name = "init_count";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace cur_count
{
    constexpr const auto addr = 0x00000839U;
    constexpr const auto name = "cur_count";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace div_conf
{
    constexpr const auto addr = 0x0000083EU;
    constexpr const auto name = "div_conf";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace self_ipi
{
    constexpr const auto addr = 0x0000083FU;
    constexpr const auto name = "self_ipi";

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }
}

//
// x2apic utility functions
//
inline auto contains(addr_type addr) noexcept
{
    return (addr & 0xFFFFFC00U) == start_addr;
}

inline auto pending(vector_type vec) noexcept
{
    auto reg = (vec & 0xE0U) >> 5U;
    auto addr = irr0::addr | reg;

    return is_bit_set(msrs::get(addr), (vec & 0x1FU));
}

inline auto level_triggered(vector_type vec) noexcept
{
    auto reg = (vec & 0xE0U) >> 5U;
    auto addr = tmr0::addr | reg;

    return is_bit_set(msrs::get(addr), (vec & 0x1FU));
}

inline auto in_service(vector_type vec) noexcept
{
    auto reg = (vec & 0xE0U) >> 5U;
    auto addr = isr0::addr | reg;

    return is_bit_set(msrs::get(addr), (vec & 0x1FU));
}

}
}

// *INDENT-ON*

#endif
