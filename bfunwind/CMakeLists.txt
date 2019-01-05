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
project(bfunwind C CXX)

init_project(bfunwind)

set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>>)
set(C_CXX $<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>)
set(BUILD_INCLUDE $<AND:${C_CXX},${BUILD}>)

target_link_libraries(bfunwind PUBLIC ${PREFIX}::bfutil)
target_include_directories(bfunwind PUBLIC
    $<${BUILD_INCLUDE}:${CMAKE_CURRENT_LIST_DIR}/include>
)
target_sources(bfunwind PRIVATE
    src/dwarf4.cpp
    src/eh_frame.cpp
    src/ia64_cxx_abi.cpp
    src/registers_intel_x64.asm
)

install(FILES include/ia64_cxx_abi.h DESTINATION include RENAME unwind.h)

fini_project()
