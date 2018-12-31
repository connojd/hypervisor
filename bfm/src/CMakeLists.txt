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
project(bfm C CXX)

set(C_CXX $<OR:$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:CXX>>)
set(LIN $<STREQUAL:${BUILD_TARGET_OS},Linux>)
set(WIN $<STREQUAL:${BUILD_TARGET_OS},Windows>)

init_project(bfm BINARY)

target_compile_definitions(bfm PUBLIC
    $<${C_CXX}:BFM_VMM_BIN_PATH=${BFM_VMM_BIN_PATH}>
    $<${C_CXX}:BFM_VMM_LIB_PATH=${BFM_VMM_LIB_PATH}>
    $<${C_CXX}:MAIN=main>
    $<${C_CXX}:ABORT=abort>
)

target_include_directories(bfm PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../include>
    $<${LIN}:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/platform/linux>>
    $<${WIN}:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/platform/windows>>

)

target_sources(bfm PRIVATE
    $<${LIN}:platform/linux/ioctl.cpp>
    $<${LIN}:platform/linux/ioctl_private.cpp>
    $<${WIN}:platform/windows/ioctl.cpp>
    $<${WIN}:platform/windows/ioctl_private.cpp>
    command_line_parser.cpp
    ioctl_driver.cpp
    main.cpp
)

target_link_libraries(bfm PRIVATE
    ${PREFIX}::bfutil
    $<$<OR:$<BOOL:${CYGWIN}>,$<BOOL:${WIN32}>>:setupapi>
)

fini_project()
