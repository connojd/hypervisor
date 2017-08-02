//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <gsl/gsl>
#include <vcpu/vcpu_intel_x64.h>
#include <vmcs/vmcs_intel_x64_debug.h>
#include <intrinsics/srs_x64.h>

vcpu_intel_x64::vcpu_intel_x64(
    vcpuid::type id,
    std::unique_ptr<debug_ring> debug_ring,
    std::unique_ptr<vmxon_intel_x64> vmxon,
    std::unique_ptr<vmcs_intel_x64> vmcs,
    std::unique_ptr<exit_handler_intel_x64> exit_handler,
    std::unique_ptr<vmcs_intel_x64_state> vmm_state,
    std::unique_ptr<vmcs_intel_x64_state> guest_state) :

    vcpu(id, std::move(debug_ring)),
    m_vmcs_launched(false),
    m_vmxon(std::move(vmxon)),
    m_vmcs(std::move(vmcs)),
    m_exit_handler(std::move(exit_handler)),
    m_vmm_state(std::move(vmm_state)),
    m_guest_state(std::move(guest_state))
{ }

void
vcpu_intel_x64::init(user_data *data)
{
    auto ___ = gsl::on_failure([&]
    { this->fini(); });

//    bfdebug << "constructing state_save\n";
    if (!m_state_save)
        m_state_save = std::make_unique<state_save_intel_x64>();

//    bfdebug << "constructing vmxon\n";
    if (!m_vmxon)
        m_vmxon = std::make_unique<vmxon_intel_x64>();

//    bfdebug << "constructing vmcs\n";
    if (!m_vmcs)
        m_vmcs = std::make_unique<vmcs_intel_x64>();

//    bfdebug << "constructing exit_handler\n";
    if (!m_exit_handler)
        m_exit_handler = std::make_unique<exit_handler_intel_x64>();

//    bfdebug << "constructing vmm_state\n";
    if (!m_vmm_state)
        m_vmm_state = std::make_unique<vmcs_intel_x64_vmm_state>();

//    bfdebug << "constructing host_vm_state\n";
    if (!m_guest_state)
        m_guest_state = std::make_unique<vmcs_intel_x64_host_vm_state>();

    m_state_save->vcpuid = this->id();
    m_state_save->vmxon_ptr = reinterpret_cast<uintptr_t>(m_vmxon.get());
    m_state_save->vmcs_ptr = reinterpret_cast<uintptr_t>(m_vmcs.get());
    m_state_save->exit_handler_ptr = reinterpret_cast<uintptr_t>(m_exit_handler.get());

    m_vmcs->set_state_save(m_state_save.get());

    m_exit_handler->set_vmcs(m_vmcs.get());
    m_exit_handler->set_state_save(m_state_save.get());

    vcpu::init(data);
}

void
vcpu_intel_x64::fini(user_data *data)
{ vcpu::fini(data); }

void
vcpu_intel_x64::run(user_data *data)
{
//    bfdebug << "executing vcpu_intel_x64::run\n";
    expects(this->is_initialized());

    if (!m_vmcs_launched)
    {
    //    bfdebug << "vmcs is not launched\n";
        m_vmcs_launched = true;

        auto ___ = gsl::on_failure([&]
        { m_vmcs_launched = false; });

        vcpu::run(data);

        auto ___ = gsl::on_failure([&]
        { vcpu::hlt(data); });

    //    bfdebug << "    calling vmxon::start\n";
        if (this->is_host_vm_vcpu())
            m_vmxon->start();

        auto ___ = gsl::on_failure([&]
        {
        //    bfdebug << "    vmxon::start failed...calling vmxon::stop \n";
            if (this->is_host_vm_vcpu())
                m_vmxon->stop();
        });

    //    bfdebug << "    launching vmcs\n";
        m_vmcs->launch(m_vmm_state.get(), m_guest_state.get());
    //    bfdebug << "    launched vmcs\n";
    }
    else
    {
    //    bfdebug << "vmcs is launched\n";
        m_vmcs->load();
        m_vmcs->resume();
    }
}

void
vcpu_intel_x64::hlt(user_data *data)
{
    bfdebug << "executing vcpu_intel_x64::hlt\n";
    if (!this->is_initialized())
        return;

    bfdebug << "vcpu is initialized\n";

    if (m_vmcs_launched)
    {
        bfdebug << "m_mvcs is launched\n";
        auto ___ = gsl::on_success([&]
        { m_vmcs_launched = false; });

        if (this->is_host_vm_vcpu()) {
            intel_x64::cr0::dump();
            intel_x64::cr4::dump();
            intel_x64::msrs::ia32_efer::dump();
            x64::rflags::dump();
            bfdebug << "cs register: " << view_as_pointer(x64::segment_register::cs::get()) << '\n';
            bfdebug << "ss access rights: " << view_as_pointer(intel_x64::vmcs::guest_ss_access_rights::dpl::get()) << '\n';
            intel_x64::vmcs::debug::dump_primary_processor_based_vm_execution_controls();
            intel_x64::vmcs::debug::dump_secondary_processor_based_vm_execution_controls();
            intel_x64::vmcs::debug::dump_vm_entry_control_fields();
            intel_x64::vmcs::debug::dump_vm_exit_control_fields();
            intel_x64::vmcs::debug::dump_pin_based_vm_execution_controls();
            bfdebug << "calling vmxon_intel_x64::stop\n";
            m_vmxon->stop();
        }
    }

    vcpu::hlt(data);
}
