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

do_test(test_all.cpp INTEGRATION)

do_test(efi/test_efi.cpp INTEGRATION)
do_test(efi/test_efi_with_interrupts.cpp INTEGRATION)

do_test(ept/enable_ept.cpp INTEGRATION)
do_test(ept/remap_page.cpp INTEGRATION)

do_test(vmexit/control_register/trap_cr0.cpp INTEGRATION)
do_test(vmexit/control_register/trap_cr3.cpp INTEGRATION)
do_test(vmexit/control_register/trap_cr4.cpp INTEGRATION)
do_test(vmexit/cpuid/trap_cpuid.cpp INTEGRATION)
do_test(vmexit/ept_misconfiguration/trap_ept_misconfiguration.cpp INTEGRATION)
do_test(vmexit/ept_violation/trap_ept_read_violation.cpp INTEGRATION)
do_test(vmexit/ept_violation/trap_ept_write_violation.cpp INTEGRATION)
do_test(vmexit/ept_violation/trap_ept_execute_violation.cpp INTEGRATION)
do_test(vmexit/external_interrupt/trap_all_interrupts.cpp INTEGRATION)
do_test(vmexit/io_instruction/trap_in_out.cpp INTEGRATION)
do_test(vmexit/monitor_trap/single_step_cpuid.cpp INTEGRATION)
do_test(vmexit/rdmsr/trap_rdmsr.cpp INTEGRATION)
do_test(vmexit/wrmsr/trap_wrmsr.cpp INTEGRATION)

do_test(vpid/enable_vpid.cpp INTEGRATION)
