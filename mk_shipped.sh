#!/bin/bash

# $1 = canonical path to build directory

if [[ $# -ne 1 ]]
then
    echo "USAGE: ./mk_shipped.sh <CMAKE_BUILD_DIR>"
    exit 42
fi

pushd $1/prefixes/x86_64-vmm-elf/lib

# Kbuild knows how to create *.o's out of *.o_shipped input files.
# In the Makefile, use *.o and Kbuild will incorporate the shipped file

ld -r -o vmm.o_shipped -L. \
    --whole-archive -lbfcrt -lbfdso -lbfvmm_entry --no-whole-archive \
    -lbfvmm_hve -lbfvmm_vcpu -lbfvmm_memory_manager -lbfvmm_debug \
    -lbfintrinsics -lc++ -lc++abi -lbfpthread -lbfunwind \
    -lm -lc -lbfsyscall

popd
