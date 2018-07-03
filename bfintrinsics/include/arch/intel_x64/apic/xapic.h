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

#ifndef INTRINSICS_XAPIC_INTEL_X64_H
#define INTRINSICS_XAPIC_INTEL_X64_H

#include <bfgsl.h>
#include <arch/intel_x64/barrier.h>

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

// *INDENT-OFF*

extern "C" uint32_t _read_xapic(uintptr_t addr) noexcept;
extern "C" void _write_xapic(uintptr_t addr, uint32_t val) noexcept;
extern "C" void _write_icr(uintptr_t icr_addr, uint64_t icr_val) noexcept;

namespace intel_x64
{
namespace xapic
{
    inline uint32_t read(uintptr_t addr) noexcept
    { return _read_xapic(addr); }

    inline void write(uintptr_t addr, uint32_t val) noexcept
    { return _write_xapic(addr, val); }

    inline void write_icr(uintptr_t icr_addr, uint64_t icr_val) noexcept
    {
        _write_xapic(icr_addr | 0x10, gsl::narrow_cast<uint32_t>(icr_val >> 32));
        ::intel_x64::barrier::mfence();
        _write_xapic(icr_addr, gsl::narrow_cast<uint32_t>(icr_val));
    }
}
}

// *INDENT-ON*

#endif
