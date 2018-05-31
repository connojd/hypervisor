/*
 * Bareflank Hypervisor
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef HYP_X86_64_H
#define HYP_X86_64_H

#include "bfefi.h"
#include "stdint.h"

#define KGDT64_SYS_TSS          0x60
#define AMD64_TSS               9

typedef union _KGDTENTRY64 {
    struct {
        UINT16 LimitLow;
        UINT16 BaseLow;
        union {
            struct {
                UINT8 BaseMiddle;
                UINT8 Flags1;
                UINT8 Flags2;
                UINT8 BaseHigh;
            } Bytes;
            struct {
                UINT32 BaseMiddle : 8;
                UINT32 Type : 5;
                UINT32 Dpl : 2;
                UINT32 Present : 1;
                UINT32 LimitHigh : 4;
                UINT32 System : 1;
                UINT32 LongMode : 1;
                UINT32 DefaultBig : 1;
                UINT32 Granularity : 1;
                UINT32 BaseHigh : 8;
            } Bits;
        };
        UINT32 BaseUpper;
        UINT32 MustBeZero;
    };
    struct {
        INT64 DataLow;
        INT64 DataHigh;
    };
} KGDTENTRY64, *PKGDTENTRY64;

#pragma pack(push,4)
typedef struct _KTSS64 {
    UINT32 Reserved0;
    UINT64 Rsp0;
    UINT64 Rsp1;
    UINT64 Rsp2;
    UINT64 Reserved1;
    UINT64 Ist[7];
    UINT64 Reserved2;
    UINT16 Reserved3;
    UINT16 IoMapBase;
} KTSS64, *PKTSS64;
#pragma pack(pop)

typedef struct _KDESCRIPTOR {
    UINT16 Pad[3];
    UINT16 Limit;
    void *Base;
} KDESCRIPTOR, *PKDESCRIPTOR;

void _writerflags(int64_t);
int64_t _readrflags();
void _sgdt(void *);
void _lgdt(void *);
void _ltr(int16_t);
uint16_t _str();
void _set_vmxe();
void _unset_vmxe();
void _set_ne();


EFI_STATUS PrepareProcessor();
EFI_STATUS CheckProcessor();

#endif
