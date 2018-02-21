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
#include <arch/intel_x64/apic/lapic.h>

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" void _sfence(void) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace xapic
{
    namespace regs
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
        regs::id,
        regs::version,
        regs::tpr,
        regs::apr,
        regs::ppr,
        regs::eoi,
        regs::rrd,
        regs::ldr,
        regs::dfr,
        regs::sivr,
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
        regs::icr_low,
        regs::icr_high,
        regs::lvt_timer,
        regs::lvt_thermal,
        regs::lvt_perf,
        regs::lvt_lint0,
        regs::lvt_lint1,
        regs::lvt_error,
        regs::init_count,
        regs::cur_count,
        regs::div_conf
    };

    inline auto supported() noexcept
    {
        return cpuid::feature_information::edx::apic::is_enabled();
    }
}
}

// *INDENT-ON*

#endif
