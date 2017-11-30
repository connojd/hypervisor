#!/bin/bash

#export TEST_RESULTS_NAME="stream-bareflank"
#export TEST_RESULTS_IDENTIFIER="stream-bareflank"
export FORCE_TIMES_TO_RUN=1

ARGS="--cpuid 4 registers 0x6000" make vmcall
#phoronix-test-suite batch-benchmark pts/stream
./stream/stream
ARGS="--cpuid 4 registers 0x7000" make vmcall
