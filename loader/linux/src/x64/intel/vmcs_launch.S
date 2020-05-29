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

.globl vmlaunch_trampoline
.type  vmlaunch_trampoline, @function
vmlaunch_trampoline:
    pop rsi

    mov rdi, VMCS_GUEST_RIP
    vmwrite rdi, rsi

    mov rdi, VMCS_GUEST_RSP
    vmwrite rdi, rsp

    mov rax, 0x0
    vmlaunch
    mov rax, 0x1

    jmp rsi
.size vmlaunch_trampoline, .-vmlaunch_trampoline

.globl vmcs_launch
.type  vmcs_launch, @function
vmcs_launch:
    call vmlaunch_trampoline
    ret
.size vmcs_launch, .-vmcs_launch
