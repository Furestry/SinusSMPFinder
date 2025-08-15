cmake_minimum_required(VERSION 3.20)
project(SinusSMPFinder)

if(NOT DEFINED ENV{CMAKE_GENERATOR_CODE_PAGE})
    set(ENV{CMAKE_GENERATOR_CODE_PAGE} "65001")
endif()

if(NOT (CMAKE_CXX_COMPILER_ID STREQUAL "GNU"))
    message(FATAL_ERROR "Требуется MinGW!")
endif()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sstool/patterns.inc")
    file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/sstool/patterns.inc" "// Пусто\n")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

set(CMAKE_CXX_FLAGS_RELEASE "-Os -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-exceptions -fvisibility=hidden")
set(CMAKE_EXE_LINKER_FLAGS "-static -s -Wl,--gc-sections")

add_executable(SinusSMPFinder
    sstool/main.cpp
    sstool/resources.o
)

target_link_libraries(SinusSMPFinder psapi)

if(WIN32)
    target_compile_options(SinusSMPFinder PRIVATE "/Zc:preprocessor")
    target_compile_definitions(SinusSMPFinder PRIVATE 
        "_WIN32_WINNT=0x0601"
        "NOMINMAX"
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(SinusSMPFinder PRIVATE "-ffunction-sections")
endif()
