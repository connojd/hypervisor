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

#ifndef INTRINSICS_X2APIC_INTEL_X64_H
#define INTRINSICS_X2APIC_INTEL_X64_H

#include <set>
#include <arch/intel_x64/apic/lapic.h>
#include <arch/intel_x64/cpuid.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_X2APIC
#ifdef SHARED_X2APIC
#define EXPORT_X2APIC EXPORT_SYM
#else
#define EXPORT_X2APIC IMPORT_SYM
#endif
#else
#define EXPORT_X2APIC
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace intel_x64
{
namespace msrs
{
    namespace ia32_x2apic_apicid
    {
        constexpr const auto addr = 0x00000802U;
        constexpr const auto name = "ia32_x2apic_apicid";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_version
    {
        constexpr const auto addr = 0x00000803U;
        constexpr const auto name = "ia32_x2apic_version";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tpr
    {
        constexpr const auto addr = 0x00000808U;
        constexpr const auto name = "ia32_x2apic_tpr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void set(value_type val) noexcept
        { _write_msr(addr, val); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_ppr
    {
        constexpr const auto addr = 0x0000080AU;
        constexpr const auto name = "ia32_x2apic_ppr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_eoi
    {
        constexpr const auto addr = 0x0000080BU;
        constexpr const auto name = "ia32_x2apic_eoi";

        inline void set(value_type val) noexcept
        { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_ldr
    {
        constexpr const auto addr = 0x0000080DU;
        constexpr const auto name = "ia32_x2apic_ldr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace logical_id
        {
            constexpr const auto mask = 0x000000000000FFFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "logical_id";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace cluster_id
        {
            constexpr const auto mask = 0x00000000FFFF0000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "cluster_id";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            logical_id::dump(level, msg);
            cluster_id::dump(level, msg);
        }
    }

    namespace ia32_x2apic_sivr
    {
        constexpr const auto addr = 0x0000080FU;
        constexpr const auto name = "ia32_x2apic_sivr";

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

    namespace ia32_x2apic_isr0
    {
        constexpr const auto addr = 0x00000810U;
        constexpr const auto name = "ia32_x2apic_isr0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_isr1
    {
        constexpr const auto addr = 0x00000811U;
        constexpr const auto name = "ia32_x2apic_isr1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_isr2
    {
        constexpr const auto addr = 0x00000812U;
        constexpr const auto name = "ia32_x2apic_isr2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_isr3
    {
        constexpr const auto addr = 0x00000813U;
        constexpr const auto name = "ia32_x2apic_isr3";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_isr4
    {
        constexpr const auto addr = 0x00000814U;
        constexpr const auto name = "ia32_x2apic_isr4";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_isr5
    {
        constexpr const auto addr = 0x00000815U;
        constexpr const auto name = "ia32_x2apic_isr5";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_isr6
    {
        constexpr const auto addr = 0x00000816U;
        constexpr const auto name = "ia32_x2apic_isr6";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_isr7
    {
        constexpr const auto addr = 0x00000817U;
        constexpr const auto name = "ia32_x2apic_isr7";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tmr0
    {
        constexpr const auto addr = 0x00000818U;
        constexpr const auto name = "ia32_x2apic_tmr0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tmr1
    {
        constexpr const auto addr = 0x00000819U;
        constexpr const auto name = "ia32_x2apic_tmr1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tmr2
    {
        constexpr const auto addr = 0x0000081AU;
        constexpr const auto name = "ia32_x2apic_tmr2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tmr3
    {
        constexpr const auto addr = 0x0000081BU;
        constexpr const auto name = "ia32_x2apic_tmr3";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tmr4
    {
        constexpr const auto addr = 0x0000081CU;
        constexpr const auto name = "ia32_x2apic_tmr4";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tmr5
    {
        constexpr const auto addr = 0x0000081DU;
        constexpr const auto name = "ia32_x2apic_tmr5";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tmr6
    {
        constexpr const auto addr = 0x0000081EU;
        constexpr const auto name = "ia32_x2apic_tmr6";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_tmr7
    {
        constexpr const auto addr = 0x0000081FU;
        constexpr const auto name = "ia32_x2apic_tmr7";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_irr0
    {
        constexpr const auto addr = 0x00000820U;
        constexpr const auto name = "ia32_x2apic_irr0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_irr1
    {
        constexpr const auto addr = 0x00000821U;
        constexpr const auto name = "ia32_x2apic_irr1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_irr2
    {
        constexpr const auto addr = 0x00000822U;
        constexpr const auto name = "ia32_x2apic_irr2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_irr3
    {
        constexpr const auto addr = 0x00000823U;
        constexpr const auto name = "ia32_x2apic_irr3";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_irr4
    {
        constexpr const auto addr = 0x00000824U;
        constexpr const auto name = "ia32_x2apic_irr4";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_irr5
    {
        constexpr const auto addr = 0x00000825U;
        constexpr const auto name = "ia32_x2apic_irr5";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_irr6
    {
        constexpr const auto addr = 0x00000826U;
        constexpr const auto name = "ia32_x2apic_irr6";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_irr7
    {
        constexpr const auto addr = 0x00000827U;
        constexpr const auto name = "ia32_x2apic_irr7";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_esr
    {
        constexpr const auto addr = 0x00000828U;
        constexpr const auto name = "ia32_x2apic_esr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void set(value_type val) noexcept
        { _write_msr(addr, val); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_lvt_cmci
    {
        constexpr const auto addr = 0x0000082FU;
        constexpr const auto name = "ia32_x2apic_lvt_cmci";

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

    namespace ia32_x2apic_icr
    {
        constexpr const auto addr = 0x00000830U;
        constexpr const auto name = "ia32_x2apic_icr";

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

        namespace destination_mode
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11ULL;
            constexpr const auto name = "destination_mode";

            constexpr const auto physical = 0U;
            constexpr const auto logical = 1U;

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
                    case physical: bfdebug_subtext(level, name, "physical", msg); break;
                    case logical: bfdebug_subtext(level, name, "logical", msg); break;
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
                }
            }
        }

        namespace level
        {
            constexpr const auto mask = 0x0000000000004000ULL;
            constexpr const auto from = 14ULL;
            constexpr const auto name = "level";

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

        namespace trigger_mode
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15ULL;
            constexpr const auto name = "trigger_mode";

            constexpr const auto edge_mode = 0U;
            constexpr const auto level_mode = 1U;

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
                    case edge_mode: bfdebug_subtext(level, name, "edge", msg); break;
                    case level_mode: bfdebug_subtext(level, name, "level", msg); break;
                }
            }
        }

        namespace destination_shorthand
        {
            constexpr const auto mask = 0x00000000000C0000ULL;
            constexpr const auto from = 18ULL;
            constexpr const auto name = "destination_shorthand";

            constexpr const auto no_shorthand = 0U;
            constexpr const auto self = 1U;
            constexpr const auto all_including_self = 2U;
            constexpr const auto all_excluding_self = 3U;

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
                    case no_shorthand: bfdebug_subtext(lev, name, "no_shorthand", msg); break;
                    case self: bfdebug_subtext(lev, name, "self", msg); break;
                    case all_including_self: bfdebug_subtext(lev, name, "all_including_self", msg); break;
                    case all_excluding_self: bfdebug_subtext(lev, name, "all_excluding_self", msg); break;
                }
            }
        }

        namespace destination_field
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32ULL;
            constexpr const auto name = "destination_field";

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

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            vector::dump(level, msg);
            delivery_mode::dump(level, msg);
            destination_mode::dump(level, msg);
            level::dump(level, msg);
            trigger_mode::dump(level, msg);
            destination_shorthand::dump(level, msg);
            destination_field::dump(level, msg);
        }
    }

    namespace ia32_x2apic_lvt_timer
    {
        constexpr const auto addr = 0x00000832U;
        constexpr const auto name = "ia32_x2apic_lvt_timer";

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

    namespace ia32_x2apic_lvt_thermal
    {
        constexpr const auto addr = 0x00000833U;
        constexpr const auto name = "ia32_x2apic_lvt_thermal";

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

    namespace ia32_x2apic_lvt_pmi
    {
        constexpr const auto addr = 0x00000834U;
        constexpr const auto name = "ia32_x2apic_lvt_pmi";

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

    namespace ia32_x2apic_lvt_lint0
    {
        constexpr const auto addr = 0x00000835U;
        constexpr const auto name = "ia32_x2apic_lvt_lint0";

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

            constexpr const auto edge_mode = 0U;
            constexpr const auto level_mode = 1U;

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
                    case edge_mode: bfdebug_subtext(level, name, "edge", msg); break;
                    case level_mode: bfdebug_subtext(level, name, "level", msg); break;
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

    namespace ia32_x2apic_lvt_lint1
    {
        constexpr const auto addr = 0x00000836U;
        constexpr const auto name = "ia32_x2apic_lvt_lint1";

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

            constexpr const auto edge_mode = 0U;
            constexpr const auto level_mode = 1U;

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
                    case edge_mode: bfdebug_subtext(level, name, "edge", msg); break;
                    case level_mode: bfdebug_subtext(level, name, "level", msg); break;
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

    namespace ia32_x2apic_lvt_error
    {
        constexpr const auto addr = 0x00000837U;
        constexpr const auto name = "ia32_x2apic_lvt_error";

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

    namespace ia32_x2apic_init_count
    {
        constexpr const auto addr = 0x00000838U;
        constexpr const auto name = "ia32_x2apic_init_count";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void set(value_type val) noexcept
        { _write_msr(addr, val); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_cur_count
    {
        constexpr const auto addr = 0x00000839U;
        constexpr const auto name = "ia32_x2apic_cur_count";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ia32_x2apic_div_conf
    {
        constexpr const auto addr = 0x0000083EU;
        constexpr const auto name = "ia32_x2apic_div_conf";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline void set(value_type val) noexcept
        { _write_msr(addr, val); }

        namespace div_val
        {
            constexpr const auto mask = 0x000000000000000BULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "div_val";

            constexpr const auto div_by_2 = 0ULL;
            constexpr const auto div_by_4 = 1ULL;
            constexpr const auto div_by_8 = 2ULL;
            constexpr const auto div_by_16 = 3ULL;
            constexpr const auto div_by_32 = 8ULL;
            constexpr const auto div_by_64 = 9ULL;
            constexpr const auto div_by_128 = 10ULL;
            constexpr const auto div_by_1 = 11ULL;

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
                    case div_by_2: bfdebug_subtext(level, name, "div_by_2", msg); break;
                    case div_by_4: bfdebug_subtext(level, name, "div_by_4", msg); break;
                    case div_by_8: bfdebug_subtext(level, name, "div_by_8", msg); break;
                    case div_by_16: bfdebug_subtext(level, name, "div_by_16", msg); break;
                    case div_by_32: bfdebug_subtext(level, name, "div_by_32", msg); break;
                    case div_by_64: bfdebug_subtext(level, name, "div_by_64", msg); break;
                    case div_by_128: bfdebug_subtext(level, name, "div_by_128", msg); break;
                    case div_by_1: bfdebug_subtext(level, name, "div_by_1", msg); break;
                }
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            div_val::dump(level, msg);
        }
    }

    namespace ia32_x2apic_self_ipi
    {
        constexpr const auto addr = 0x0000083FU;
        constexpr const auto name = "ia32_x2apic_self_ipi";

        inline void set(value_type val) noexcept
        { _write_msr(addr, val); }

        namespace vector
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "vector";

            inline void set(value_type val) noexcept
            { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

            inline auto set(value_type msr, value_type val) noexcept
            { return set_bits(msr, mask, val << from); }
        }
    }
}

namespace x2apic
{
    namespace regs
    {
        const lapic::reg_info id = { (msrs::ia32_x2apic_apicid::addr & 0xFF), true, false };
        const lapic::reg_info version = { (msrs::ia32_x2apic_version::addr & 0xFF), true, false };
        const lapic::reg_info tpr = { (msrs::ia32_x2apic_tpr::addr & 0xFF), true, true };
        const lapic::reg_info ppr = { (msrs::ia32_x2apic_ppr::addr & 0xFF), true, false };
        const lapic::reg_info eoi = { (msrs::ia32_x2apic_eoi::addr & 0xFF), false, true };
        const lapic::reg_info ldr = { (msrs::ia32_x2apic_ldr::addr & 0xFF), true, false };
        const lapic::reg_info svr = { (msrs::ia32_x2apic_sivr::addr & 0xFF), true, true };
        const lapic::reg_info isr0 = { (msrs::ia32_x2apic_isr0::addr & 0xFF), true, false };
        const lapic::reg_info isr1 = { (msrs::ia32_x2apic_isr1::addr & 0xFF), true, false };
        const lapic::reg_info isr2 = { (msrs::ia32_x2apic_isr2::addr & 0xFF), true, false };
        const lapic::reg_info isr3 = { (msrs::ia32_x2apic_isr3::addr & 0xFF), true, false };
        const lapic::reg_info isr4 = { (msrs::ia32_x2apic_isr4::addr & 0xFF), true, false };
        const lapic::reg_info isr5 = { (msrs::ia32_x2apic_isr5::addr & 0xFF), true, false };
        const lapic::reg_info isr6 = { (msrs::ia32_x2apic_isr6::addr & 0xFF), true, false };
        const lapic::reg_info isr7 = { (msrs::ia32_x2apic_isr7::addr & 0xFF), true, false };
        const lapic::reg_info tmr0 = { (msrs::ia32_x2apic_tmr0::addr & 0xFF), true, false };
        const lapic::reg_info tmr1 = { (msrs::ia32_x2apic_tmr1::addr & 0xFF), true, false };
        const lapic::reg_info tmr2 = { (msrs::ia32_x2apic_tmr2::addr & 0xFF), true, false };
        const lapic::reg_info tmr3 = { (msrs::ia32_x2apic_tmr3::addr & 0xFF), true, false };
        const lapic::reg_info tmr4 = { (msrs::ia32_x2apic_tmr4::addr & 0xFF), true, false };
        const lapic::reg_info tmr5 = { (msrs::ia32_x2apic_tmr5::addr & 0xFF), true, false };
        const lapic::reg_info tmr6 = { (msrs::ia32_x2apic_tmr6::addr & 0xFF), true, false };
        const lapic::reg_info tmr7 = { (msrs::ia32_x2apic_tmr7::addr & 0xFF), true, false };
        const lapic::reg_info irr0 = { (msrs::ia32_x2apic_irr0::addr & 0xFF), true, false };
        const lapic::reg_info irr1 = { (msrs::ia32_x2apic_irr1::addr & 0xFF), true, false };
        const lapic::reg_info irr2 = { (msrs::ia32_x2apic_irr2::addr & 0xFF), true, false };
        const lapic::reg_info irr3 = { (msrs::ia32_x2apic_irr3::addr & 0xFF), true, false };
        const lapic::reg_info irr4 = { (msrs::ia32_x2apic_irr4::addr & 0xFF), true, false };
        const lapic::reg_info irr5 = { (msrs::ia32_x2apic_irr5::addr & 0xFF), true, false };
        const lapic::reg_info irr6 = { (msrs::ia32_x2apic_irr6::addr & 0xFF), true, false };
        const lapic::reg_info irr7 = { (msrs::ia32_x2apic_irr7::addr & 0xFF), true, false };
        const lapic::reg_info esr = { (msrs::ia32_x2apic_esr::addr & 0xFF), true, true };
        const lapic::reg_info lvt_cmci = { (msrs::ia32_x2apic_lvt_cmci::addr & 0xFF), true, true };
        const lapic::reg_info icr = { (msrs::ia32_x2apic_icr::addr & 0xFF), true, true };
        const lapic::reg_info lvt_timer = { (msrs::ia32_x2apic_lvt_timer ::addr & 0xFF), true, true };
        const lapic::reg_info lvt_thermal = { (msrs::ia32_x2apic_lvt_thermal::addr & 0xFF), true, true };
        const lapic::reg_info lvt_perf = { (msrs::ia32_x2apic_lvt_pmi::addr & 0xFF), true, true };
        const lapic::reg_info lvt_lint0 = { (msrs::ia32_x2apic_lvt_lint0::addr & 0xFF), true, true };
        const lapic::reg_info lvt_lint1 = { (msrs::ia32_x2apic_lvt_lint1::addr & 0xFF), true, true };
        const lapic::reg_info lvt_error = { (msrs::ia32_x2apic_lvt_error::addr & 0xFF), true, true };
        const lapic::reg_info init_count = { (msrs::ia32_x2apic_init_count::addr & 0xFF), true, true };
        const lapic::reg_info cur_count = { (msrs::ia32_x2apic_cur_count::addr & 0xFF), true, false };
        const lapic::reg_info div_conf = { (msrs::ia32_x2apic_div_conf::addr & 0xFF), true, true };
        const lapic::reg_info self_ipi = { (msrs::ia32_x2apic_self_ipi::addr & 0xFF), false, true };
    }

    using reg_info_set_type = const std::set<intel_x64::lapic::reg_info>;
    reg_info_set_type reg_set = {
        regs::id,
        regs::version,
        regs::tpr,
        regs::ppr,
        regs::eoi,
        regs::ldr,
        regs::svr,
        regs::isr0,
        regs::isr1,
        regs::isr2,
        regs::isr3,
        regs::isr4,
        regs::isr5,
        regs::isr6,
        regs::isr7,
        regs::tmr0,
        regs::tmr1,
        regs::tmr2,
        regs::tmr3,
        regs::tmr4,
        regs::tmr5,
        regs::tmr6,
        regs::tmr7,
        regs::irr0,
        regs::irr1,
        regs::irr2,
        regs::irr3,
        regs::irr4,
        regs::irr5,
        regs::irr6,
        regs::irr7,
        regs::esr,
        regs::lvt_cmci,
        regs::icr,
        regs::lvt_timer,
        regs::lvt_thermal,
        regs::lvt_perf,
        regs::lvt_lint0,
        regs::lvt_lint1,
        regs::lvt_error,
        regs::init_count,
        regs::cur_count,
        regs::div_conf,
        regs::self_ipi
    };

    using namespace intel_x64::msrs;
    using addr_set_type = const std::array<lapic::addr_type, 44>;
    addr_set_type addr_set = {{
        ia32_x2apic_apicid::addr,
        ia32_x2apic_version::addr,
        ia32_x2apic_tpr::addr,
        ia32_x2apic_ppr::addr,
        ia32_x2apic_eoi::addr,
        ia32_x2apic_ldr::addr,
        ia32_x2apic_sivr::addr,
        ia32_x2apic_isr0::addr,
        ia32_x2apic_isr1::addr,
        ia32_x2apic_isr2::addr,
        ia32_x2apic_isr3::addr,
        ia32_x2apic_isr4::addr,
        ia32_x2apic_isr5::addr,
        ia32_x2apic_isr6::addr,
        ia32_x2apic_isr7::addr,
        ia32_x2apic_tmr0::addr,
        ia32_x2apic_tmr1::addr,
        ia32_x2apic_tmr2::addr,
        ia32_x2apic_tmr3::addr,
        ia32_x2apic_tmr4::addr,
        ia32_x2apic_tmr5::addr,
        ia32_x2apic_tmr6::addr,
        ia32_x2apic_tmr7::addr,
        ia32_x2apic_irr0::addr,
        ia32_x2apic_irr1::addr,
        ia32_x2apic_irr2::addr,
        ia32_x2apic_irr3::addr,
        ia32_x2apic_irr4::addr,
        ia32_x2apic_irr5::addr,
        ia32_x2apic_irr6::addr,
        ia32_x2apic_irr7::addr,
        ia32_x2apic_esr::addr,
        ia32_x2apic_lvt_cmci::addr,
        ia32_x2apic_icr::addr,
        ia32_x2apic_lvt_timer::addr,
        ia32_x2apic_lvt_thermal::addr,
        ia32_x2apic_lvt_pmi::addr,
        ia32_x2apic_lvt_lint0::addr,
        ia32_x2apic_lvt_lint1::addr,
        ia32_x2apic_lvt_error::addr,
        ia32_x2apic_init_count::addr,
        ia32_x2apic_cur_count::addr,
        ia32_x2apic_div_conf::addr,
        ia32_x2apic_self_ipi::addr
    }};

    inline auto supported() noexcept
    {
        return cpuid::feature_information::ecx::x2apic::is_enabled();
    }
}

/// x2APIC subclass of the lapic abstract base class
///
/// This class implements the abstract lapic interface for x2apic
/// mode. It is marked final because it is intended to interact
/// directly with x2apic hardware.
///
struct EXPORT_X2APIC x2apic_control final : public lapic_control
{
    //
    // Check if guest physical address is an APIC register and the desired
    // read / write operation is allowed.
    //
    // @return offset if supplied address maps to a valid register and the
    //    operation is allowed.
    // @return -1 if the supplied address doesn't map to a valid register or the
    //    operation is not allowed.
    //
    // @param addr - guest physical address of desired register
    // @param op - the desired operation (read / write)
    //
    int validate_gpa_op(const gpa_type addr, const reg_op op) noexcept override
    {
        auto reg_set_iter = x2apic::reg_set.find((addr & 0xFF0U) >> 4);

        if (reg_set_iter != x2apic::reg_set.end()) {
            switch (op) {
                case read:
                    if (reg_set_iter->readable) {
                        return (addr & 0xFF0U) >> 4;
                    }
                    break;

                case write:
                    if (reg_set_iter->writeable) {
                        return (addr & 0xFF0U) >> 4;
                    }
                    break;

                default:
                    bferror_info(0, "invalid register operation");
                    return -1;
            }
        }

        return -1;
    }

    //
    // Check if MSR address is an APIC register and the desired read / write
    // operation is allowed.
    //
    // @return offset if supplied address maps to a valid register and the
    //    operation is allowed.
    // @return -1 if the supplied address doesn't map to a valid register or the
    //    operation is not allowed.
    //
    // @param addr - MSR address of desired register
    // @param op - the desired operation (read / write)
    //
    int validate_msr_op(const msrs::field_type msr, const reg_op op) noexcept override
    {
        if (msr < lapic::msr_start_reg || msr > lapic::msr_end_reg) {
            return -1;
        }
        auto reg_set_iter = x2apic::reg_set.find(msr & 0xFFU);

        if (reg_set_iter != x2apic::reg_set.end()) {
            switch (op) {
                case read:
                    if (reg_set_iter->readable) {
                        return msr & 0xFFU;
                    }
                    break;

                case write:
                    if (reg_set_iter->writeable) {
                        return msr & 0xFFU;
                    }
                    break;

                default:
                    bferror_info(0, "invalid register operation");
                    return -1;
            }
        }

        return -1;
    }

    value_type read_register(const uint32_t offset) noexcept override
    { return msrs::get(offset | lapic::msr_start_reg); }

    void write_register(const uint32_t offset, const value_type val) noexcept override
    { msrs::set((offset | lapic::msr_start_reg), val); }


    //
    // Register reads
    //
    value_type read_id() noexcept override
    { return msrs::ia32_x2apic_apicid::get(); }

    value_type read_version() noexcept override
    { return msrs::ia32_x2apic_version::get(); }

    value_type read_tpr() noexcept override
    { return msrs::ia32_x2apic_tpr::get(); }

    value_type read_ldr() noexcept override
    { return msrs::ia32_x2apic_ldr::get(); }

    value_type read_svr() noexcept override
    { return msrs::ia32_x2apic_sivr::get(); }

    value_type read_icr() noexcept override
    { return msrs::ia32_x2apic_icr::get(); }


    value_type read_isr(const index idx) noexcept override
    {
        auto addr = msrs::ia32_x2apic_isr0::addr | idx;
        return msrs::get(addr);
    }

    value_type read_tmr(const index idx) noexcept override
    {
        auto addr = msrs::ia32_x2apic_tmr0::addr | idx;
        return msrs::get(addr);
    }

    value_type read_irr(const index idx) noexcept override
    {
        auto addr = msrs::ia32_x2apic_irr0::addr | idx;
        return msrs::get(addr);
    }

    value_type read_lvt(const lvt_reg reg) noexcept override
    {
        switch (reg) {
            case cmci:
                return msrs::ia32_x2apic_lvt_cmci::get();
            case timer:
                return msrs::ia32_x2apic_lvt_timer::get();
            case thermal:
                return msrs::ia32_x2apic_lvt_thermal::get();
            case perf:
                return msrs::ia32_x2apic_lvt_pmi::get();
            case lint0:
                return msrs::ia32_x2apic_lvt_lint0::get();
            case lint1:
                return msrs::ia32_x2apic_lvt_lint1::get();
            case error:
                return msrs::ia32_x2apic_lvt_error::get();

            default:
                bferror_info(0, "invalid lvt_reg");
                return 0;
        }
    }

    value_type read_count(const count_reg reg) noexcept override
    {
        switch (reg) {
            case initial:
                return msrs::ia32_x2apic_init_count::get();
            case current:
                return msrs::ia32_x2apic_cur_count::get();

            default:
                bferror_info(0, "invalid count_reg");
                return 0;
        }
    }

    value_type read_div_config() noexcept override
    { return msrs::ia32_x2apic_div_conf::get(); }


    //
    // Register writes
    //
    void write_eoi() noexcept override
    { msrs::ia32_x2apic_eoi::set(0x0ULL); }

    void write_tpr(const value_type tpr) noexcept override
    { msrs::ia32_x2apic_tpr::set(tpr); }

    void write_svr(const value_type svr) noexcept override
    { msrs::ia32_x2apic_sivr::set(svr); }

    void write_icr(const value_type icr) noexcept override
    { msrs::ia32_x2apic_icr::set(icr); }

    void write_lvt(const lvt_reg reg, const value_type val) noexcept override
    {
        switch (reg) {
            case cmci:
                msrs::ia32_x2apic_lvt_cmci::set(val);
                return;
            case timer:
                msrs::ia32_x2apic_lvt_timer::set(val);
                return;
            case thermal:
                msrs::ia32_x2apic_lvt_thermal::set(val);
                return;
            case perf:
                msrs::ia32_x2apic_lvt_pmi::set(val);
                return;
            case lint0:
                msrs::ia32_x2apic_lvt_lint0::set(val);
                return;
            case lint1:
                msrs::ia32_x2apic_lvt_lint1::set(val);
                return;
            case error:
                msrs::ia32_x2apic_lvt_error::set(val);
                return;

            default:
                bferror_info(0, "invalid lvt_reg");
                return;
        }
    }

    void write_init_count(const value_type count) noexcept override
    { msrs::ia32_x2apic_init_count::set(count); }

    void write_div_config(const value_type config) noexcept override
    { msrs::ia32_x2apic_div_conf::set(config); }


    //
    // Send a self-ipi
    //
    // A self-ipi is a self-targeted, edge-triggered, fixed interrupt
    // with the specified vector.
    //
    // @param vec - the vector of the self-ipi
    //
    void write_self_ipi(const vector_type vec) noexcept override
    { msrs::ia32_x2apic_self_ipi::vector::set(vec); }

    //
    // Check trigger-mode
    //
    // @return true if the supplied vector is set in the TMR
    // @return false if the supplied vector is clear in the TMR
    //
    // @param vec - the vector for which the check occurs.
    //
    // @note to ensure an accurate result, the caller should mask
    // the vector prior to the call
    //
    bool level_triggered(const vector_type vec) noexcept override
    {
        auto reg = (vec & 0xE0) >> 5;
        auto bit = 1ULL << (vec & 0x1F);
        switch (reg) {
            case 0:
                return msrs::ia32_x2apic_tmr0::get() & bit;
            case 1:
                return msrs::ia32_x2apic_tmr1::get() & bit;
            case 2:
                return msrs::ia32_x2apic_tmr2::get() & bit;
            case 3:
                return msrs::ia32_x2apic_tmr3::get() & bit;
            case 4:
                return msrs::ia32_x2apic_tmr4::get() & bit;
            case 5:
                return msrs::ia32_x2apic_tmr5::get() & bit;
            case 6:
                return msrs::ia32_x2apic_tmr6::get() & bit;
            case 7:
                return msrs::ia32_x2apic_tmr7::get() & bit;

            default:
                bferror_info(0, "invalid vector_type");
                return false;
        }
    }

    //
    // Check if in-service
    //
    // @return true if the supplied vector is set in the ISR
    // @return false if the supplied vector is clear in the ISR
    //
    // @param vec - the vector for which the check occurs.
    //
    // @note to ensure an accurate result, the caller should mask
    // the vector prior to the call
    //
    bool in_service(const vector_type vec) noexcept override
    {
        auto reg = (vec & 0xE0) >> 5;
        auto bit = 1ULL << (vec & 0x1F);
        switch (reg) {
            case 0:
                return msrs::ia32_x2apic_isr0::get() & bit;
            case 1:
                return msrs::ia32_x2apic_isr1::get() & bit;
            case 2:
                return msrs::ia32_x2apic_isr2::get() & bit;
            case 3:
                return msrs::ia32_x2apic_isr3::get() & bit;
            case 4:
                return msrs::ia32_x2apic_isr4::get() & bit;
            case 5:
                return msrs::ia32_x2apic_isr5::get() & bit;
            case 6:
                return msrs::ia32_x2apic_isr6::get() & bit;
            case 7:
                return msrs::ia32_x2apic_isr7::get() & bit;

            default:
                bferror_info(0, "invalid vector_type");
                return false;
        }
    }

    //
    // Default operations
    //
    ~x2apic_control() = default;
    x2apic_control() = default;
    x2apic_control(x2apic_control &&) = default;
    x2apic_control &operator=(x2apic_control &&) = default;

    x2apic_control(const x2apic_control &) = delete;
    x2apic_control &operator=(const x2apic_control &) = delete;
};

}

#endif
