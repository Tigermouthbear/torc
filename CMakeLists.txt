cmake_minimum_required(VERSION 3.17)
project(torc C)

set(CMAKE_C_STANDARD 99)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(torc src/torc.c src/torc.h src/torcmds.c src/torcmds.h)
target_link_libraries(torc Threads::Threads OpenSSL::Crypto)

add_executable(torc_test test/test.c test/mongoose.c test/mongoose.h)
target_link_libraries(torc_test torc)