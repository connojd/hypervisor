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

add_executable(vmm)

set(VMM_ENTRY ${CMAKE_INSTALL_PREFIX}/lib/libbfvmm_entry.a)
get_target_property(VMM_CRT ${PREFIX}::bfcrt LOCATION)

target_link_libraries(vmm PUBLIC "--whole-archive ${VMM_ENTRY} --no-whole-archive")
target_link_libraries(vmm PUBLIC bfvmm_hve)
target_link_libraries(vmm PUBLIC bfvmm_vcpu)
target_link_libraries(vmm PUBLIC bfvmm_memory_manager)
target_link_libraries(vmm PUBLIC bfvmm_debug)
target_link_libraries(vmm PUBLIC ${PREFIX}::bfintrinsics)
target_link_libraries(vmm PUBLIC ${CMAKE_INSTALL_PREFIX}/lib/libc++.a)
target_link_libraries(vmm PUBLIC ${CMAKE_INSTALL_PREFIX}/lib/libc++abi.a)
target_link_libraries(vmm PUBLIC ${PREFIX}::bfpthread)
target_link_libraries(vmm PUBLIC ${PREFIX}::bfunwind)
target_link_libraries(vmm PUBLIC ${CMAKE_INSTALL_PREFIX}/lib/libm.a)
target_link_libraries(vmm PUBLIC ${CMAKE_INSTALL_PREFIX}/lib/libc.a)
target_link_libraries(vmm PUBLIC ${PREFIX}::bfsyscall)
target_link_libraries(vmm PUBLIC "--whole-archive ${VMM_CRT} --no-whole-archive")

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
target_sources(vmm PRIVATE $<${X64}:arch/intel_x64/vcpu_factory.cpp>)

install(TARGETS vmm DESTINATION bin EXPORT bfvmm-${PREFIX}-targets)
