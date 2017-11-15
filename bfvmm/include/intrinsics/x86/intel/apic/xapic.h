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

#ifndef XAPIC_INTEL_X64_H
#define XAPIC_INTEL_X64_H

#include <set>
#include <atomic>
#include <intrinsics/x86/intel/apic/lapic.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_XAPIC
#ifdef SHARED_XAPIC
#define EXPORT_XAPIC EXPORT_SYM
#else
#define EXPORT_XAPIC IMPORT_SYM
#endif
#else
#define EXPORT_XAPIC
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace intel_x64
{
namespace xapic
{
    namespace registers
    {
        const lapic::reg_info id = { (0x020U >> 4), true, true };
        const lapic::reg_info version = { (0x030U >> 4), true, false };
        const lapic::reg_info tpr = { (0x080U >> 4), true, true };
        const lapic::reg_info apr = { (0x090U >> 4), true, false };
        const lapic::reg_info ppr = { (0x0A0U >> 4), true, false };
        const lapic::reg_info eoi = { (0x0B0U >> 4), false, true };
        const lapic::reg_info rrd = { (0x0C0U >> 4), true, false };
        const lapic::reg_info ldr = { (0x0D0U >> 4), true, true };
        const lapic::reg_info dfr = { (0x0E0U >> 4), true, true };
        const lapic::reg_info sivr = { (0x0F0U >> 4), true, true };
        const lapic::reg_info isr0 = { (0x100U >> 4), true, false };
        const lapic::reg_info isr1 = { (0x110U >> 4), true, false };
        const lapic::reg_info isr2 = { (0x120U >> 4), true, false };
        const lapic::reg_info isr3 = { (0x130U >> 4), true, false };
        const lapic::reg_info isr4 = { (0x140U >> 4), true, false };
        const lapic::reg_info isr5 = { (0x150U >> 4), true, false };
        const lapic::reg_info isr6 = { (0x160U >> 4), true, false };
        const lapic::reg_info isr7 = { (0x170U >> 4), true, false };
        const lapic::reg_info tmr0 = { (0x180U >> 4), true, false };
        const lapic::reg_info tmr1 = { (0x190U >> 4), true, false };
        const lapic::reg_info tmr2 = { (0x1A0U >> 4), true, false };
        const lapic::reg_info tmr3 = { (0x1B0U >> 4), true, false };
        const lapic::reg_info tmr4 = { (0x1C0U >> 4), true, false };
        const lapic::reg_info tmr5 = { (0x1D0U >> 4), true, false };
        const lapic::reg_info tmr6 = { (0x1E0U >> 4), true, false };
        const lapic::reg_info tmr7 = { (0x1F0U >> 4), true, false };
        const lapic::reg_info irr0 = { (0x200U >> 4), true, false };
        const lapic::reg_info irr1 = { (0x210U >> 4), true, false };
        const lapic::reg_info irr2 = { (0x220U >> 4), true, false };
        const lapic::reg_info irr3 = { (0x230U >> 4), true, false };
        const lapic::reg_info irr4 = { (0x240U >> 4), true, false };
        const lapic::reg_info irr5 = { (0x250U >> 4), true, false };
        const lapic::reg_info irr6 = { (0x260U >> 4), true, false };
        const lapic::reg_info irr7 = { (0x270U >> 4), true, false };
        const lapic::reg_info esr = { (0x280U >> 4), true, false };
        const lapic::reg_info lvt_cmci = { (0x2F0U >> 4), true, true };
        const lapic::reg_info icr_low = { (0x300U >> 4), true, true };
        const lapic::reg_info icr_high = { (0x310U >> 4), true, true };
        const lapic::reg_info lvt_timer = { (0x320U >> 4), true, true };
        const lapic::reg_info lvt_thermal = { (0x330U >> 4), true, true };
        const lapic::reg_info lvt_perf = { (0x340U >> 4), true, true };
        const lapic::reg_info lvt_lint0 = { (0x350U >> 4), true, true };
        const lapic::reg_info lvt_lint1 = { (0x360U >> 4), true, true };
        const lapic::reg_info lvt_error = { (0x370U >> 4), true, true };
        const lapic::reg_info init_count = { (0x380U >> 4), true, true };
        const lapic::reg_info cur_count = { (0x390U >> 4), true, false };
        const lapic::reg_info div_conf = { (0x3E0U >> 4), true, true };
    }

    using reg_info_set_type = const std::set<intel_x64::lapic::reg_info>;
    reg_info_set_type reg_set = {
        registers::id,
        registers::version,
        registers::tpr,
        registers::apr,
        registers::ppr,
        registers::eoi,
        registers::rrd,
        registers::ldr,
        registers::dfr,
        registers::sivr,
        registers::isr0,
        registers::isr1,
        registers::isr2,
        registers::isr3,
        registers::isr4,
        registers::isr5,
        registers::isr6,
        registers::isr7,
        registers::tmr0,
        registers::tmr1,
        registers::tmr2,
        registers::tmr3,
        registers::tmr4,
        registers::tmr5,
        registers::tmr6,
        registers::tmr7,
        registers::irr0,
        registers::irr1,
        registers::irr2,
        registers::irr3,
        registers::irr4,
        registers::irr5,
        registers::irr6,
        registers::irr7,
        registers::esr,
        registers::lvt_cmci,
        registers::icr_low,
        registers::icr_high,
        registers::lvt_timer,
        registers::lvt_thermal,
        registers::lvt_perf,
        registers::lvt_lint0,
        registers::lvt_lint1,
        registers::lvt_error,
        registers::init_count,
        registers::cur_count,
        registers::div_conf
    };

    inline auto supported() noexcept
    {
        return cpuid::feature_information::edx::apic::is_enabled();
    }
}

/// xAPIC subclass of the lapic abstract base class
///
/// This class implements the abstract lapic interface for xapic
/// mode. It is marked final because it is intended to interact
/// directly with xapic hardware.
///
struct EXPORT_XAPIC xapic_control final : public lapic_control
{
    using apic_base_type = uintptr_t;

    //
    // Check if guest physical address is an APIC register and the desired
    // read / write operation is allowed.
    //
    // @return offset if supplied address maps to a valid register and the
    //    operation is allowed.
    // @return -1 if the supplied address doesn't map to a valid register or the
    //    operation is not allowed.
    //
    // @param addr - MSR address of desired register
    // @param op - the desired operation (read / write)
    //
    int validate_gpa_op(uintptr_t addr, reg_op op) noexcept override
    {
        auto reg_set_iter = xapic::reg_set.find((addr & 0xFF0U) >> 4);

        if (reg_set_iter != xapic::reg_set.end()) {
            switch (op) {
                case read:
                    if (reg_set_iter->read)
                        return (addr & 0xFF0U) >> 4;
                    else
                        return -1;
                case write:
                    if (reg_set_iter->write)
                        return (addr & 0xFF0U) >> 4;
                    else
                        return -1;

                default:
                    bferror_info(0, "invalid register operation");
                    return -1;
            }
        }

        else
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
    // @param addr - guest physical address of desired register
    // @param op - the desired operation (read / write)
    //
    int validate_msr_op(msrs::field_type msr, reg_op op) noexcept override
    {
        if (msr < lapic::msr_start_reg || msr > lapic::msr_end_reg)
            return -1;
        auto reg_set_iter = xapic::reg_set.find(msr & 0xFFU);

        if (reg_set_iter != xapic::reg_set.end()) {
            switch (op) {
                case read:
                    if (reg_set_iter->read)
                        return msr & 0xFFU;
                    else
                        return -1;
                case write:
                    if (reg_set_iter->write)
                        return msr & 0xFFU;
                    else
                        return -1;

                default:
                    bferror_info(0, "invalid register operation");
                    return -1;
            }
        }

        else
            return -1;
    }

    value_type read_register(uint32_t offset) noexcept override
    { return m_apic_page[offset << 2]; }

    void write_register(uint32_t offset, value_type val) noexcept override
    { m_apic_page[offset << 2] = gsl::narrow_cast<uint32_t>(val); }


    //
    // Register reads
    //
    value_type read_id() noexcept override
    { return read_register(xapic::registers::id.offset); }

    value_type read_version() noexcept override
    { return read_register(xapic::registers::version.offset); }

    value_type read_tpr() noexcept override
    { return read_register(xapic::registers::tpr.offset); }

    value_type read_ldr() noexcept override
    { return read_register(xapic::registers::ldr.offset); }

    value_type read_svr() noexcept override
    { return read_register(xapic::registers::sivr.offset); }

    value_type read_icr() noexcept override
    {
        value_type low = read_register(xapic::registers::icr_low.offset);
        value_type high = read_register(xapic::registers::icr_high.offset);
        return (high << 32) | low;
    }

    value_type read_isr(index idx) noexcept override
    {
        auto offset = xapic::registers::isr0.offset | idx;
        return read_register(offset);
    }

    value_type read_tmr(index idx) noexcept override
    {
        auto offset = xapic::registers::tmr0.offset | idx;
        return read_register(offset);
    }

    value_type read_irr(index idx) noexcept override
    {
        auto offset = xapic::registers::irr0.offset | idx;
        return read_register(offset);
    }

    value_type read_lvt(lvt_reg reg) noexcept override
    {
        switch (reg) {
            case cmci:
                return read_register(xapic::registers::lvt_cmci.offset);
            case timer:
                return read_register(xapic::registers::lvt_timer.offset);
            case thermal:
                return read_register(xapic::registers::lvt_thermal.offset);
            case perf:
                return read_register(xapic::registers::lvt_perf.offset);
            case lint0:
                return read_register(xapic::registers::lvt_lint0.offset);
            case lint1:
                return read_register(xapic::registers::lvt_lint1.offset);
            case error:
                return read_register(xapic::registers::lvt_error.offset);

            default:
                bferror_info(0, "invalid lvt_reg");
                return 0;
        }
    }

    value_type read_count(count_reg reg) noexcept override
    {
        switch (reg) {
            case initial:
                return read_register(xapic::registers::init_count.offset);
            case current:
                return read_register(xapic::registers::cur_count.offset);

            default:
                bferror_info(0, "invalid count_reg");
                return 0;
        }
    }

    value_type read_div_config() noexcept override
    { return read_register(xapic::registers::div_conf.offset); }


    //
    // Register writes
    //
    void write_eoi() noexcept override
    { write_register(xapic::registers::eoi.offset, 0x0ULL); }

    void write_tpr(value_type tpr) noexcept override
    { write_register(xapic::registers::tpr.offset, tpr); }

    void write_svr(value_type svr) noexcept override
    { write_register(xapic::registers::sivr.offset, svr); }

    void write_icr(value_type icr) noexcept override
    {
        value_type low = icr & 0x00000000FFFFFFFFULL;
        value_type high = (icr & 0xFFFFFFFF00000000ULL) >> 32;
        write_register(xapic::registers::icr_high.offset, high);
        std::atomic_thread_fence(std::memory_order_release);
        write_register(xapic::registers::icr_low.offset, low);
    }

    void write_icr_low(value_type icr_low) noexcept override
    { write_register(xapic::registers::icr_low.offset, icr_low); }

    void write_icr_high(value_type icr_high) noexcept override
    { write_register(xapic::registers::icr_high.offset, icr_high); }

    void write_lvt(lvt_reg reg, value_type val) noexcept override
    {
        switch (reg) {
            case cmci:
                write_register(xapic::registers::lvt_cmci.offset, val);
                return;
            case timer:
                write_register(xapic::registers::lvt_timer.offset, val);
                return;
            case thermal:
                write_register(xapic::registers::lvt_thermal.offset, val);
                return;
            case perf:
                write_register(xapic::registers::lvt_perf.offset, val);
                return;
            case lint0:
                write_register(xapic::registers::lvt_lint0.offset, val);
                return;
            case lint1:
                write_register(xapic::registers::lvt_lint1.offset, val);
                return;
            case error:
                write_register(xapic::registers::lvt_error.offset, val);
                return;

            default:
                bferror_info(0, "invalid lvt_reg");
                return;
        }
    }

    void write_init_count(value_type count) noexcept override
    { write_register(xapic::registers::init_count.offset, count); }

    void write_div_config(value_type config) noexcept override
    { write_register(xapic::registers::div_conf.offset, config); }


    //
    // Send a self-ipi
    //
    // A self-ipi is a self-targeted, edge-triggered, fixed interrupt
    // with the specified vector.
    //
    // @param vec - the vector of the self-ipi
    //
    void write_self_ipi(vector_type vec) noexcept override
    {
        value_type val = 0x0ULL | (vec & 0xFFULL) | 0x44000ULL;
        write_icr(val);
    }

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
    bool level_triggered(vector_type vec) noexcept override
    {
        auto reg = (vec & 0xE0) >> 5;
        auto bit = 1ULL << (vec & 0x1F);
        switch (reg) {
            case 0:
                return read_register(xapic::registers::tmr0.offset) & bit;
            case 1:
                return read_register(xapic::registers::tmr1.offset) & bit;
            case 2:
                return read_register(xapic::registers::tmr2.offset) & bit;
            case 3:
                return read_register(xapic::registers::tmr3.offset) & bit;
            case 4:
                return read_register(xapic::registers::tmr4.offset) & bit;
            case 5:
                return read_register(xapic::registers::tmr5.offset) & bit;
            case 6:
                return read_register(xapic::registers::tmr6.offset) & bit;
            case 7:
                return read_register(xapic::registers::tmr7.offset) & bit;

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
    bool in_service(vector_type vec) noexcept override
    {
        auto reg = (vec & 0xE0) >> 5;
        auto bit = 1ULL << (vec & 0x1F);
        switch (reg) {
            case 0:
                return read_register(xapic::registers::isr0.offset) & bit;
            case 1:
                return read_register(xapic::registers::isr1.offset) & bit;
            case 2:
                return read_register(xapic::registers::isr2.offset) & bit;
            case 3:
                return read_register(xapic::registers::isr3.offset) & bit;
            case 4:
                return read_register(xapic::registers::isr4.offset) & bit;
            case 5:
                return read_register(xapic::registers::isr5.offset) & bit;
            case 6:
                return read_register(xapic::registers::isr6.offset) & bit;
            case 7:
                return read_register(xapic::registers::isr7.offset) & bit;

            default:
                bferror_info(0, "invalid vector_type");
                return false;
        }
    }

    //
    // Default operations
    //
    ~xapic_control() = default;
    xapic_control() = default;
    xapic_control(uint32_t* base)
    { m_apic_page = base; }
    xapic_control(xapic_control &&) = default;
    xapic_control &operator=(xapic_control &&) = default;

    xapic_control(const xapic_control &) = delete;
    xapic_control &operator=(const xapic_control &) = delete;


private:

    uint32_t* m_apic_page;

};

}

#endif
