/* SPDX-License-Identifier: GPL-2.0 OR MIT */

/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define VMCS_GUEST_RSP 0x0000681C
#define VMCS_GUEST_RIP 0x0000681E

.globl handle_vmexit

.code64
.intel_syntax noprefix

.globl exit_handler_entry
.type  exit_handler_entry, @function
exit_handler_entry:

    cli

    mov [fs:0x000], rax
    mov [fs:0x008], rbx
    mov [fs:0x010], rcx
    mov [fs:0x018], rdx
    mov [fs:0x020], rbp
    mov [fs:0x028], rsi
    mov [fs:0x030], rdi
    mov [fs:0x038], r8
    mov [fs:0x040], r9
    mov [fs:0x048], r10
    mov [fs:0x050], r11
    mov [fs:0x058], r12
    mov [fs:0x060], r13
    mov [fs:0x068], r14
    mov [fs:0x070], r15

    mov rsi, VMCS_GUEST_RIP
    vmread [fs:0x078], rsi
    mov rsi, VMCS_GUEST_RSP
    vmread [fs:0x080], rsi

    mov rdi, [fs:0x098]
    call handle_vmexit

    /* We shouldn't get this far */
    hlt

.size exit_handler_entry, .-exit_handler_entry
