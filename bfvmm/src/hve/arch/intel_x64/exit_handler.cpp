//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/exit_handler.h>

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool trace_vmexits{false};

struct vmexit_desc {
    uint32_t reason;
    uint64_t guest_cr3;
    uint64_t data[2];
} __attribute__((packed));

struct vmexit_desc exit_reason_list[64]{0};
uint32_t exit_reason_head{0};

namespace bfvmm::intel_x64
{

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

exit_handler::exit_handler(
    gsl::not_null<vcpu *> vcpu)
{ bfignored(vcpu); }

void
exit_handler::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handlers_array.at(reason).push_front(d); }

void
exit_handler::add_exit_handler(
    const handler_delegate_t &d)
{ m_exit_handlers.push_front(d); }

}

extern "C"  void
handle_exit(
    vcpu_t *vcpu, exit_handler_t *exit_handler)
{
    guard_exceptions([&]() {

        uint32_t reason = vmcs_n::exit_reason::basic_exit_reason::get();

        if ((vcpu->id() == 0) || vcpu->is_guest_vcpu()) {
            using namespace vmcs_n::exit_reason;

            struct vmexit_desc *desc = &exit_reason_list[exit_reason_head];

            switch (reason) {
            case vmcs_n::exit_reason::basic_exit_reason::cpuid:
                desc->data[0] = vcpu->rax();
                desc->data[1] = vcpu->rcx();
                break;
            case vmcs_n::exit_reason::basic_exit_reason::external_interrupt:
                desc->data[0] = vmcs_n::vm_exit_interruption_information::get();
                break;
            case vmcs_n::exit_reason::basic_exit_reason::wrmsr:
                desc->data[0] = ((vcpu->rdx() & 0xFFFFFFFFU) << 32) | (vcpu->rax() & 0xFFFFFFFFU);
                desc->data[1] = vcpu->rcx();
                break;
            case vmcs_n::exit_reason::basic_exit_reason::vmcall:
                desc->data[0] = vcpu->rax();
                break;
            default:
                break;
            }

            bool parent = (vcpu->id() == 0);

            desc->reason = reason | (parent ? (1U << 31) : 0);
            desc->guest_cr3 = vmcs_n::guest_cr3::get();

            exit_reason_head = (exit_reason_head + 1U) & 0x3FU;
        }

        for (const auto &d : exit_handler->m_exit_handlers) {
            d(vcpu);
        }

        const auto &handlers = exit_handler->m_exit_handlers_array.at(reason);

        for (const auto &d : handlers) {
            if (d(vcpu)) {
                vcpu->run();
            }
        }
    });

    vcpu->halt("unhandled vm exit");
}
