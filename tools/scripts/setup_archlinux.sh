#!/bin/bash -e
#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

source $(dirname $0)/setup_common.sh

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

check_folder

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------

parse_arguments $@

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

install_common_packages() {
    sudo pacman -Syu
    sudo pacman -S --needed --noconfirm ca-certificates
    sudo pacman -S --needed --noconfirm base-devel
    sudo pacman -S --needed --noconfirm linux-headers
    sudo pacman -S --needed --noconfirm nasm
    sudo pacman -S --needed --noconfirm clang
    sudo pacman -S --needed --noconfirm texinfo
    sudo pacman -S --needed --noconfirm cmake
}

# ------------------------------------------------------------------------------
# Setup System
# ------------------------------------------------------------------------------

case $( grep ^ID_LIKE= /etc/os-release | cut -d'=' -f 2 ) in
archlinux|"\"arch\"")
    install_common_packages
    ;;

*)
    echo "This version of Arch Linux is not supported"
    exit 1

esac

# ------------------------------------------------------------------------------
# Setup Build Environment
# ------------------------------------------------------------------------------

setup_build_environment
