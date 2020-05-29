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

.code64
.intel_syntax noprefix

.globl vmcs_resume
.type  vmcs_resume, @function
vmcs_resume:

    mov rsi, VMCS_GUEST_RSP
    vmwrite rsi, [fs:0x080]
    mov rsi, VMCS_GUEST_RIP
    vmwrite rsi, [fs:0x078]

    mov r15, [fs:0x070]
    mov r14, [fs:0x068]
    mov r13, [fs:0x060]
    mov r12, [fs:0x058]
    mov r11, [fs:0x050]
    mov r10, [fs:0x048]
    mov r9,  [fs:0x040]
    mov r8,  [fs:0x038]
    mov rdi, [fs:0x030]
    mov rsi, [fs:0x028]
    mov rbp, [fs:0x020]
    mov rdx, [fs:0x018]
    mov rcx, [fs:0x010]
    mov rbx, [fs:0x008]

    sti
    mov rax, [fs:0x000]

    vmresume

    /* We shouldn't get this far */
    hlt

.size vmcs_resume, .-vmcs_resume
