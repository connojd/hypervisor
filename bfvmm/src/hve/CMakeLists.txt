#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

add_library(bfvmm_hve)
target_link_libraries(bfvmm_hve PUBLIC bfvmm)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(WIN $<BOOL:${WIN32}>)
set(MOCK $<BOOL:${ENABLE_MOCKING}>)
set(NEED_ASM $<AND:$<NOT:${WIN}>,$<NOT:${MOCK}>>)

target_sources(bfvmm_hve PRIVATE
    $<${X64}:arch/intel_x64/check_vmcs_control_fields.cpp>
    $<${X64}:arch/intel_x64/check_vmcs_guest_fields.cpp>
    $<${X64}:arch/intel_x64/check_vmcs_host_fields.cpp>
    $<${X64}:arch/intel_x64/exception.cpp>
    $<${X64}:arch/intel_x64/nmi.cpp>
    $<${X64}:arch/intel_x64/exit_handler.cpp>
    $<${X64}:arch/intel_x64/vcpu.cpp>
    $<${X64}:arch/intel_x64/vmcs.cpp>
    $<${X64}:arch/intel_x64/vmx.cpp>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/exception.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/nmi.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/exit_handler_entry.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/vmcs_launch.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/vmcs_promote.asm>
    $<$<AND:${X64},${NEED_ASM}>:arch/intel_x64/vmcs_resume.asm>
)

install(TARGETS bfvmm_hve DESTINATION lib EXPORT bfvmm)
install(DIRECTORY ../../include/hve/ DESTINATION include/bfvmm/hve)
