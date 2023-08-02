#!/bin/bash

cp CMakeLists.libcotp.macOS.txt vendors/libcotp/CMakeLists.txt

# new build
if [ "$1" == "new" ]; then
    rm -rf build/release
    cmake -S . -B build/release -D CMAKE_BUILD_TYPE=Release
    cd build/release
    make
    cd ../..
# continuous build
elif [ "$1" == "con" ]; then
    cd build/release
    make
    cd ../..
fi

cp CMakeLists.libcotp.bak.txt vendors/libcotp/CMakeLists.txt
