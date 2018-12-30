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
project(bfcrt C CXX)

init_project(bfcrt)

set(ARM $<STREQUAL:${BUILD_TARGET_ARCH},aarch64>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(WIN $<BOOL:${WIN32}>)
set(X64_AND_NOT_WIN $<AND:${X64},$<NOT:${WIN}>>)

target_compile_options(bfcrt PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wno-main>)
target_link_libraries(bfcrt PUBLIC bfutil)
target_link_options(bfcrt INTERFACE
    "SHELL:--whole-archive ${VMM_PREFIX_PATH}/lib/libbfcrt.a --no-whole-archive"
)
target_sources(bfcrt PRIVATE
    crt.cpp
    $<${X64_AND_NOT_WIN}:start_x64.asm>
    $<${ARM}:start_x64.S>
)

fini_project()
