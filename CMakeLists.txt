cmake_minimum_required(VERSION 3.10)
project(SinusSMPFinder)

if(NOT DEFINED ENV{CMAKE_GENERATOR_CODE_PAGE})
    set(ENV{CMAKE_GENERATOR_CODE_PAGE} "65001")
endif()

if(NOT (CMAKE_CXX_COMPILER_ID STREQUAL "GNU"))
    message(FATAL_ERROR "Требуется MinGW!")
endif()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/patterns.inc")
    file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/patterns.inc" "// Пусто\n")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

set(CMAKE_CXX_FLAGS_RELEASE "-Os -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-exceptions -fvisibility=hidden")
set(CMAKE_EXE_LINKER_FLAGS "-static -s -Wl,--gc-sections")

add_executable(SinusSMPFinder main.cpp resources.o)

target_link_libraries(SinusSMPFinder psapi)
