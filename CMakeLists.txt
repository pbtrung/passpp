cmake_minimum_required(VERSION 3.20)
project(passpp VERSION 0.9999)

# SQLiteCpp
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SQLITECPP_RUN_CPPCHECK OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPLINT OFF CACHE BOOL "" FORCE)
add_subdirectory(vendors/SQLiteCpp)

# crypto++
set(CRYPTOPP_BUILD_TESTING OFF)
add_subdirectory(vendors/cryptopp-cmake)
# libcotp
add_subdirectory(vendors/libcotp)
# json
set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(vendors/json)

add_executable(passpp src/main.cpp)
target_link_libraries(passpp SQLiteCpp sqlite3 pthread dl cryptopp cotp nlohmann_json::nlohmann_json argon2)
