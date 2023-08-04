#!/bin/bash

cp CMakeLists.sqlite3.macOS.txt vendors/SQLiteCpp/sqlite3/CMakeLists.txt

# new build
if [ "$1" == "new" ]; then
    # rm -rf build/release
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

cp CMakeLists.sqlite3.bak.txt vendors/SQLiteCpp/sqlite3/CMakeLists.txt
