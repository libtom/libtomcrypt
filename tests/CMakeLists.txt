# SPDX-License-Identifier: Unlicense
#
# LibTomCrypt, modular cryptographic library -- Tom St Denis
#

cmake_minimum_required(VERSION 3.10)

set(LTC_TEST test-ltc)

# This file can be included from the top level or used stand-alone
if(PROJECT_NAME)
    set(LIBRARY_NAME ${PROJECT_NAME})
else()
    # Define an independent project and all the necessary stuff around
    project(${LTC_TEST}
        LANGUAGES C)
    set(LIBRARY_NAME libtomcrypt)
    find_package(${LIBRARY_NAME})
    include(CTest)
    if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        set(CMAKE_BUILD_TYPE "Release")
    endif()
endif()

#-----------------------------------------------------------------------------
# Compose CFLAGS etc.
#-----------------------------------------------------------------------------

if(NOT MSVC)
    set(CMAKE_C_FLAGS_DEBUG "-g3 -O1")
endif()

#-----------------------------------------------------------------------------
# demo target
#-----------------------------------------------------------------------------
include(sources.cmake)
set(PRIVATE_HEADERS
    common.h
    tomcrypt_test.h
)

add_executable(${LTC_TEST}
    ${SOURCES}
    ${PRIVATE_HEADERS}
)

target_include_directories(${LTC_TEST} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    $<$<STREQUAL:${PROJECT_NAME},${LTC_TEST}>:${CMAKE_CURRENT_SOURCE_DIR}/..>
)

target_link_libraries(${LTC_TEST} PRIVATE
    ${LIBRARY_NAME}
)

target_compile_options(${LTC_TEST} PRIVATE
    $<$<STREQUAL:$<TARGET_PROPERTY:${LIBRARY_NAME},TYPE>,SHARED_LIBRARY>:-DLTC_TEST_DYNAMIC>
    -DCMAKE_SOURCE_DIR=\"${CMAKE_SOURCE_DIR}\"
    ${LTC_C_FLAGS}
)
target_link_options(${LTC_TEST} BEFORE PUBLIC
    ${LTC_LD_FLAGS}
)

#-----------------------------------------------------------------------------
# CTest
#-----------------------------------------------------------------------------
add_test(NAME ${LTC_TEST} COMMAND ${LTC_TEST})

find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full")