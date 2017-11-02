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

#ifndef VMCS_INTEL_X64_EVENT_H
#define VMCS_INTEL_X64_EVENT_H

#include <bfbitmanip.h>

#include <intrinsics/x86/intel/vmcs/32bit_guest_state_fields.h>
#include <intrinsics/x86/intel/vmcs/32bit_control_fields.h>
#include <intrinsics/x86/intel/vmcs/natural_width_guest_state_fields.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

using vector_type = uint8_t;

// This functions implements the checks described in #1 of section 33.3.3.4
inline auto irq_window_open() noexcept
{
    namespace guest_intr_state = guest_interruptibility_state;

    if (guest_rflags::interrupt_enable_flag::is_disabled()) {
        return false;
    }

    auto gis = guest_intr_state::get();
    if (guest_intr_state::blocking_by_sti::is_enabled(gis)) {
        return false;
    }

    if (guest_intr_state::blocking_by_mov_ss::is_enabled(gis)) {
        return false;
    }

    switch (guest_activity_state::get()) {
        case guest_activity_state::active:
        case guest_activity_state::hlt:
            return true;
        default:
            return false;
    }
}

inline auto validate_irq_injection(vector_type vec) noexcept
{
    using namespace vm_entry_interruption_information;

    constexpr auto type = interruption_type::external_interrupt;
    auto info = 0ULL;

    info = vector::set(info, vec);
    info = interruption_type::set(info, type);
    info = valid_bit::enable(info);
    set(info);

    return;
}

}
}

// *INDENT-ON*
#endif
