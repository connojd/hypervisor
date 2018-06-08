#
# Bareflank Hypervisor
# Copyright (C) 2018 Assured Information Security, Inc.
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

set(EFI_TARGET_NAME includeos)
set(EFI_VMM_NAME includeos)
set(EFI_VMM ${VMM_PREFIX_PATH}/bin/${EFI_VMM_NAME})
set(EFI_VMM_OBJ ${EFI_OUTPUT_DIR}/${EFI_VMM_NAME}.o)
#set(EFI_TARGET_NAME bfloader)

add_custom_command(
    OUTPUT ${EFI_VMM_OBJ}
    COMMAND ${CMAKE_COMMAND} -E copy ${EFI_VMM} ${EFI_VMM_NAME}
    COMMAND ${CMAKE_OBJCOPY}
    ARGS -I binary -O elf64-x86-64 -B i386
    ARGS --redefine-sym _binary_${EFI_VMM_NAME}_start=target_vmm_start
    ARGS --redefine-sym _binary_${EFI_VMM_NAME}_end=target_vmm_end
    ARGS ${EFI_VMM_NAME} ${EFI_VMM_OBJ}
    DEPENDS ${EFI_VMM}
    WORKING_DIRECTORY ${EFI_OUTPUT_DIR}
    COMMENT "Hypervisor using: ${EFI_VMM_NAME}"
)

# Location of libos.a produced by includeos build system
#set(INCLUDEOS_LIB_NAME includeos)
#set(INCLUDEOS_LIB_OBJ ${EFI_OUTPUT_DIR}/${INCLUDEOS_LIB_NAME}.o)
#set(INCLUDEOS_LIB ${VMM_PREFIX_PATH}/bin/${INCLUDEOS_LIB_NAME})
#set(INCLUDEOS_TARGET_NAME includeos)

#add_custom_command(
#    OUTPUT ${INCLUDEOS_LIB_OBJ}
#    COMMAND ${CMAKE_COMMAND} -E copy ${INCLUDEOS_LIB} ${INCLUDEOS_LIB_NAME}
#    COMMAND ${CMAKE_OBJCOPY}
#    ARGS -I binary -O elf64-x86-64 -B i386
#    ARGS --redefine-sym _binary_${INCLUDEOS_LIB_NAME}_start=target_vmm_start
#    ARGS --redefine-sym _binary_${INCLUDEOS_LIB_NAME}_end=target_vmm_end
#    ARGS ${INCLUDEOS_LIB_NAME} ${INCLUDEOS_LIB_OBJ}
#    DEPENDS ${EFI_VMM}
#    WORKING_DIRECTORY ${EFI_OUTPUT_DIR}
#    COMMENT "OS using: ${INCLUDEOS_LIB_NAME}"
#)

list(APPEND VMM_SOURCES
    ${VMM_PREFIX_PATH}/lib/crt0-efi-${BUILD_TARGET_ARCH}.o
    efi_main.c
    boot.c
    ${EFI_VMM_OBJ}
)

#list(APPEND INCLUDEOS_SOURCES
#    ${VMM_PREFIX_PATH}/lib/crt0-efi-${BUILD_TARGET_ARCH}.o
#    efi_main.c
#    boot.c
#    ${INCLUDEOS_LIB_OBJ}
#)

#add_library(${INCLUDEOS_TARGET_NAME} SHARED ${INCLUDEOS_SOURCES})
#set_property(TARGET ${INCLUDEOS_TARGET_NAME} PROPERTY SKIP_BUILD_RPATH TRUE)

add_library(${EFI_TARGET_NAME} SHARED ${VMM_SOURCES})
set_property(TARGET ${EFI_TARGET_NAME} PROPERTY SKIP_BUILD_RPATH TRUE)

add_library(libgnuefi STATIC IMPORTED)
set_target_properties(libgnuefi PROPERTIES IMPORTED_LOCATION
    ${VMM_PREFIX_PATH}/lib/libgnuefi.a
)
add_dependencies(libgnuefi gnuefi)

add_library(libefi STATIC IMPORTED)
set_target_properties(libefi PROPERTIES IMPORTED_LOCATION
    ${VMM_PREFIX_PATH}/lib/libefi.a
)
add_dependencies(libefi gnuefi)

target_link_libraries(${EFI_TARGET_NAME} libgnuefi libefi)
#target_link_libraries(${INCLUDEOS_TARGET_NAME} libgnuefi libefi)

set(EFI_LINKER_SCRIPT ${VMM_PREFIX_PATH}/lib/elf_${BUILD_TARGET_ARCH}_efi.lds)
target_link_libraries(${EFI_TARGET_NAME} -T ${EFI_LINKER_SCRIPT})
#target_link_libraries(${INCLUDEOS_TARGET_NAME} -T ${EFI_LINKER_SCRIPT})

file(READ ${EFI_SOURCES_CMAKE} EXTERNAL_SOURCES)

foreach(src ${EXTERNAL_SOURCES})
    message(STATUS "Adding EFI external source: ${src}")
    target_sources(${EFI_TARGET_NAME} PRIVATE ${src})
endforeach()

#target_sources(${INCLUDEOS_TARGET_NAME} PRIVATE ${SOURCE_BFDRIVER_DIR}/src/platform/efi/efi_includeos/includeos.c)
#target_sources(${INCLUDEOS_TARGET_NAME} PRIVATE ${SOURCE_BFDRIVER_DIR}/src/platform/efi/efi_includeos/platform.c)
#target_sources(${INCLUDEOS_TARGET_NAME} PRIVATE ${SOURCE_BFDRIVER_DIR}/src/common.c)

add_custom_command(
    TARGET ${EFI_TARGET_NAME}
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY}
    ARGS -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel -j .rela -j .rel.* -j .rela.* -j .rel*
    ARGS -j .rela* -j .reloc --target=efi-app-${BUILD_TARGET_ARCH} lib${EFI_TARGET_NAME}.so ${EFI_OUTPUT_DIR}/${EFI_TARGET_NAME}.efi
    MAIN_DEPENDENCY lib${EFI_TARGET_NAME}.so
    COMMENT "Linking ${EFI_TARGET_NAME}.efi"
)

#add_custom_command(
#    TARGET ${INCLUDEOS_TARGET_NAME}
#    POST_BUILD
#    COMMAND ${CMAKE_OBJCOPY}
#    ARGS -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel -j .rela -j .rel.* -j .rela.* -j .rel*
#    ARGS -j .rela* -j .reloc --target=efi-app-${BUILD_TARGET_ARCH} lib${INCLUDEOS_TARGET_NAME}.so ${EFI_OUTPUT_DIR}/${INCLUDEOS_TARGET_NAME}.efi
#    MAIN_DEPENDENCY lib${INCLUDEOS_TARGET_NAME}.so
#    COMMENT "Linking ${INCLUDEOS_TARGET_NAME}.efi"
#)

install(FILES ${EFI_OUTPUT_DIR}/${EFI_TARGET_NAME}.efi DESTINATION bin)
#install(FILES ${EFI_OUTPUT_DIR}/${INCLUDEOS_TARGET_NAME}.efi DESTINATION bin)
