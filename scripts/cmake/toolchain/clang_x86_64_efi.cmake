#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

if(CMAKE_INSTALL_PREFIX)
    set(ENV{CMAKE_INSTALL_PREFIX} "${CMAKE_INSTALL_PREFIX}")
else()
    set(CMAKE_INSTALL_PREFIX "$ENV{CMAKE_INSTALL_PREFIX}")
endif()

set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_C_COMPILER clang)
set(LD_BIN ld)

set(EFI_C_FLAGS "-mno-red-zone -mno-avx -fpic  -g -O2 -Wall -Wextra -fshort-wchar -fno-strict-aliasing -fno-merge-all-constants -ffreestanding -fno-stack-protector -fno-stack-check -DCONFIG_x86_64 -DGNU_EFI_USE_MS_ABI --std=c11 -D__KERNEL__")

set(EFI_LD_FLAGS "-nostdlib --warn-common --no-undefined --fatal-warnings -shared -Bsymbolic -defsym=EFI_SUBSYSTEM=0xa --no-undefined")

set(CMAKE_C_COMPILE_OBJECT "clang <DEFINES> <INCLUDES> ${EFI_C_FLAGS} -o <OBJECT> -c <SOURCE>")

set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_C_CREATE_SHARED_LIBRARY "ld ${EFI_LD_FLAGS} <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
