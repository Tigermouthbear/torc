cmake_minimum_required(VERSION 3.17)
project(torc C)

set(CMAKE_C_STANDARD 99)
set(THREADS_PREFER_PTHREAD_FLAG ON)

set(TORC_BUILD_TYPE "static" CACHE STRING "The type of library to create: static, object, or shared (default static).")
set(TORC_FIND_OPENSSL ON CACHE BOOL "Whether cmake should find the openssl package (the open OpenSSL::Crypto alias must be set if this is OFF).")

find_package(Threads REQUIRED)
if(${TORC_FIND_OPENSSL})
    find_package(OpenSSL REQUIRED)
endif()

add_library(torc-object OBJECT src/torc.c src/torc.h src/torcmds.c src/torcmds.h)
target_link_libraries(torc-object Threads::Threads OpenSSL::Crypto)

if(NOT TORC_BUILD_TYPE STREQUAL "object")
    if(TORC_BUILD_TYPE STREQUAL "shared")
        add_library(torc SHARED $<TARGET_OBJECTS:torc-object>)
    else()
        add_library(torc STATIC $<TARGET_OBJECTS:torc-object>)
    endif()

    target_link_libraries(torc Threads::Threads OpenSSL::Crypto)

    if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR) # only build test when not being used as a library/subdirectory
        add_executable(torc_test test/test.c test/mongoose.c test/mongoose.h)
        target_link_libraries(torc_test torc)
    endif()
endif()