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

cmake_minimum_required(VERSION 3.10)
project(bfintrinsics C CXX)

init_project(bfintrinsics)

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(VMM $<AND:$<STREQUAL:${PREFIX},vmm>,$<BOOL:${BUILD_VMM}>>)
set(VMM_X64 $<AND:${VMM},${X64}>)

target_link_libraries(bfintrinsics PUBLIC ${PREFIX}::bfutil)
target_sources(bfintrinsics PRIVATE
    $<${VMM_X64}:arch/x64/cache.asm>
    $<${VMM_X64}:arch/x64/cpuid.asm>
    $<${VMM_X64}:arch/x64/gdt.asm>
    $<${VMM_X64}:arch/x64/idt.asm>
    $<${VMM_X64}:arch/x64/msrs.asm>
    $<${VMM_X64}:arch/x64/pm.asm>
    $<${VMM_X64}:arch/x64/portio.asm>
    $<${VMM_X64}:arch/x64/rdtsc.asm>
    $<${VMM_X64}:arch/x64/rflags.asm>
    $<${VMM_X64}:arch/x64/srs.asm>
    $<${VMM_X64}:arch/x64/tlb.asm>
    $<${VMM_X64}:arch/intel_x64/barrier.asm>
    $<${VMM_X64}:arch/intel_x64/bit.asm>
    $<${VMM_X64}:arch/intel_x64/crs.asm>
    $<${VMM_X64}:arch/intel_x64/drs.asm>
    $<${VMM_X64}:arch/intel_x64/pause.asm>
    $<${VMM_X64}:arch/intel_x64/vmx.asm>
)

install(DIRECTORY ../include/ DESTINATION include)

fini_project()
