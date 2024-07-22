cmake_minimum_required(VERSION 3.10)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(lwIP)

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)

set (LWIP_DEFINITIONS LWIP_DEBUG=1)

include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)

add_definitions(-fPIC)
add_definitions(-fno-lto)

set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_DIR}/contrib/"
    "${LWIP_DIR}/contrib/ports/unix/port/include"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/contrib/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/unix/Filelists.cmake)

add_library(lwip SHARED compat.c)
target_include_directories(lwip PRIVATE ${LWIP_INCLUDE_DIRS})
target_link_libraries(lwip
    -Wl,--whole-archive lwipcore
    -Wl,--no-whole-archive
    ${LWIP_SANITIZER_LIBS}
    lwipcontribportunix
)

function(add_c_preprocessor_command)
    # Add custom command to run C preprocessor.
    #
    # Source: https://stackoverflow.com/a/66896673
    #
    # Arguments
    #   OUTPUT          output file
    #   SOURCE          input file
    #   TARGET          CMake target to inherit compile definitions, include directories, and compile options
    #   EXTRA_C_FLAGS   extra compiler flags added after all flags inherited from the TARGET

    set(one_value_args TARGET SOURCE OUTPUT)
    set(multi_value_args EXTRA_C_FLAGS)
    cmake_parse_arguments(CPP "" "${one_value_args}" "${multi_value_args}" ${ARGN})

    string(TOUPPER ${CMAKE_BUILD_TYPE} build_type)
    string(REPLACE " " ";" c_flags "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${build_type}}")

    add_custom_command(
        OUTPUT ${CPP_OUTPUT}
        COMMAND ${CMAKE_C_COMPILER}
            "-I$<JOIN:$<TARGET_PROPERTY:${CPP_TARGET},INCLUDE_DIRECTORIES>,;-I>"
            ${c_flags}
            $<TARGET_PROPERTY:${CPP_TARGET},COMPILE_OPTIONS>
            ${CPP_EXTRA_C_FLAGS}
            -D "__attribute__(ARGS)=" -D "__restrict=" -D "__builtin_va_list=int" -D "__asm__(ARGS)="
            -D "__extension__=" -D "__inline="
            -E -P ${CPP_SOURCE} -o ${CPP_OUTPUT}
        COMMAND_EXPAND_LISTS VERBATIM
        IMPLICIT_DEPENDS C ${CPP_SOURCE}
        DEPENDS ${CPP_SOURCE})
endfunction()

add_c_preprocessor_command(
  OUTPUT "headers.h"
  SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/headers.in.h"
  TARGET lwip
  EXTRA_C_FLAGS ""
)

add_custom_command(
    OUTPUT "headers.py"
    COMMAND 
        ${CMAKE_CURRENT_SOURCE_DIR}/make_headers.sh
        ${CMAKE_BINARY_DIR}/headers.h
        ${CMAKE_BINARY_DIR}/headers.py
    DEPENDS "headers.h"
)
add_custom_target(headers ALL DEPENDS "headers.py")
