#!/bin/bash

set -e

pushd ./build

cmake \
    -G "Unix Makefiles" \
    -DENABLE_DEVELOPER_MODE=ON \
    -DENABLE_UNITTESTING=ON \
    ..

popd
