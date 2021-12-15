cmake_minimum_required(VERSION 3.17)
project(torc C)

set(CMAKE_C_STANDARD 99)
set(THREADS_PREFER_PTHREAD_FLAG ON)

set(TORC_BUILD_TYPE "static" CACHE STRING "The type of library to create: static, object, or shared (default static).")

find_package(Threads REQUIRED)
find_package(OpenSSL) # is REQUIRED, but set to not so that it can be added by root projects (used for android)

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