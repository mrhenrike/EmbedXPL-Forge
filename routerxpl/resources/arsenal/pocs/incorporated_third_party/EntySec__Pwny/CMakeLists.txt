#
# MIT License
#
# Copyright (c) 2020-2026 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

cmake_minimum_required(VERSION 3.10.0)
project(libpwny VERSION 1.0.0)

option(DEBUG "Build in debug mode" OFF)
option(MAIN "Build main executable" OFF)
option(BUNDLE "Build as bundle (macOS/iOS)" OFF)
option(SHARED "Build shared object instead" OFF)
option(PLUGINS "Build tab plugins" OFF)

set(SOURCE src/main/main.c CACHE STRING "File to build as executable")

if (DEBUG)
    add_compile_definitions(DEBUG)
endif()

# Strip build paths from binaries (prevents source path leaks)
add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=./)

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    include_directories(include/compat include/mingw)
    file(GLOB PWNY_SOURCES src/*.c src/compat/*.c src/mingw/*.c)

    add_compile_definitions(__windows__)

elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    include_directories(include/posix)
    file(GLOB PWNY_SOURCES src/*.c src/posix/*.c)

    add_compile_definitions(__macintosh__)

    if(BUNDLE)
        add_link_options(-bundle)
    endif()

elseif(CMAKE_SYSTEM_NAME STREQUAL iOS)
    include_directories(include/posix)
    file(GLOB PWNY_SOURCES src/*.c src/posix/*.c)

    add_compile_definitions(__iphone__)

    if(BUNDLE)
        add_compile_definitions(IS_BUNDLE)
    endif()

elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
    include_directories(include/posix)
    file(GLOB PWNY_SOURCES src/*.c src/posix/*.c)
    add_compile_definitions(__linux__)

endif()

list(FILTER PWNY_SOURCES EXCLUDE REGEX "tab_lite\\.c$")
list(FILTER PWNY_SOURCES EXCLUDE REGEX "tab_dll_api\\.c$")
list(FILTER PWNY_SOURCES EXCLUDE REGEX "pe_load\\.c$")
add_library(pwny STATIC ${PWNY_SOURCES})

set_property(TARGET pwny PROPERTY C_STANDART 99)
set_property(TARGET pwny PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(pwny PROPERTIES OUTPUT_NAME pwny)
include_directories(include api deps/build/${CMAKE_SYSTEM_TARGET}/include)

if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    target_compile_definitions(pwny PRIVATE
        __windows__
        CURL_STATICLIB
    )
endif()

if(MAIN)
    file(GLOB MAIN_SOURCES ${SOURCE})
    add_executable(main ${MAIN_SOURCES})

    target_link_directories(main PRIVATE deps/build/${CMAKE_SYSTEM_TARGET}/lib)
    target_link_libraries(main PRIVATE
    pwny
    pawn
    sigar
    eio
    ev
    curl
    z
    mbedx509
    mbedtls
    mbedcrypto
    pthread
)

    if(CMAKE_SYSTEM_NAME STREQUAL Linux)
        target_link_libraries(main PRIVATE injector)
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL Windows)
        enable_language(ASM)
        target_link_libraries(main PRIVATE ws2_32 netapi32 version crypt32 advapi32 secur32 ole32 oleaut32)
        if(SHARED)
            target_link_options(main PRIVATE -shared)
        else()
            target_link_options(main PRIVATE --static)
        endif()

    elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
        target_compile_options(main PRIVATE -fobjc-arc)
        target_link_libraries(main PRIVATE "-framework Foundation"
                                           "-framework IOKit"
                                           "-framework AVFoundation"
                                           "-framework AppKit"
                                           "-framework CoreMedia"
                                           "-framework CoreImage")

    elseif(CMAKE_SYSTEM_NAME STREQUAL iOS)
        target_link_libraries(main PRIVATE "-framework Foundation"
                                           "-framework UIKitCore"
                                           "-framework AVFCapture"
                                           "-framework AVFCore"
                                           "-framework AVFAudio"
                                           "-framework CoreMedia"
                                           "-framework CoreVideo"
                                           "-framework CoreGraphics"
                                           "-framework CoreImage"
                                           "-framework BackBoardServices"
                                           "-framework MediaRemote"
                                           "-framework MediaPlayer"
                                           "-framework SpringBoardServices"
                                           "-framework CoreLocation"
                                           "MobileGestalt")

    elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
        target_link_libraries(main PRIVATE pthread)
        if(SHARED)
            target_link_options(main PRIVATE -shared -fPIC)
        else()
            if(CMAKE_SYSTEM_PROCESSOR STREQUAL x64)
                target_link_options(main PRIVATE -static-pie -Wl,-z,max-page-size=4096)
            else()
                target_link_options(main PRIVATE -static-pie)
            endif()
        endif()
    endif()
endif()

# Service executable (Windows only)
if(MAIN AND CMAKE_SYSTEM_NAME STREQUAL Windows)
    add_executable(pwny_service src/main/service.c src/main/stager_x64.S)
    target_link_directories(pwny_service PRIVATE deps/build/${CMAKE_SYSTEM_TARGET}/lib)
    target_link_libraries(pwny_service PRIVATE
        pwny pawn sigar eio ev curl z mbedx509 mbedtls mbedcrypto)
    target_link_libraries(pwny_service PRIVATE
        ws2_32 netapi32 version crypt32 advapi32 secur32 ole32 oleaut32 pthread)
    target_link_options(pwny_service PRIVATE --static)
endif()

# Migration DLL (Windows only)
if(MAIN AND CMAKE_SYSTEM_NAME STREQUAL Windows)
    enable_language(ASM)
    add_library(pwny_dll SHARED
        src/main/dll.c
        src/main/stager_x64.S
        src/main/obfuscate_x64.S
        src/main/gate_x64.S
    )
    target_link_directories(pwny_dll PRIVATE deps/build/${CMAKE_SYSTEM_TARGET}/lib)
    target_link_libraries(pwny_dll PRIVATE
        pwny pawn sigar eio ev curl z mbedx509 mbedtls mbedcrypto)
    target_link_libraries(pwny_dll PRIVATE
        ws2_32 netapi32 version crypt32 advapi32 secur32 ole32 oleaut32 pthread)
    target_compile_options(pwny_dll PRIVATE -Os -ffunction-sections -fdata-sections)
    target_link_options(pwny_dll PRIVATE -static-libgcc -Wl,--gc-sections -Wl,--strip-all -Wl,--exclude-all-symbols)
    set_target_properties(pwny_dll PROPERTIES
        OUTPUT_NAME pwny
        PREFIX ""
        SUFFIX ".dll"
    )
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

# Lightweight tab library for plugins (no heavy deps)
set(TAB_SOURCES
    src/tab_lite.c
    src/tlv.c
    src/queue.c
    src/log.c
)
if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    file(GLOB TAB_COMPAT_SOURCES src/compat/*.c)
    list(APPEND TAB_SOURCES ${TAB_COMPAT_SOURCES})
endif()

add_library(tab STATIC ${TAB_SOURCES})
set_property(TARGET tab PROPERTY C_STANDARD 99)
set_property(TARGET tab PROPERTY POSITION_INDEPENDENT_CODE ON)
set_target_properties(tab PROPERTIES OUTPUT_NAME tab)

# Windows-only: DLL tab library for in-process tab plugins
if(CMAKE_SYSTEM_NAME STREQUAL Windows)
    set(TAB_DLL_SOURCES
        src/mingw/tab_dll_api.c
        src/tlv.c
        src/queue.c
        src/log.c
    )
    file(GLOB TAB_DLL_COMPAT_SOURCES src/compat/*.c)
    list(APPEND TAB_DLL_SOURCES ${TAB_DLL_COMPAT_SOURCES})

    add_library(tab_dll STATIC ${TAB_DLL_SOURCES})
    set_property(TARGET tab_dll PROPERTY C_STANDARD 99)
    set_property(TARGET tab_dll PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_target_properties(tab_dll PROPERTIES OUTPUT_NAME tab_dll)
endif()

# Build tab plugins
if(PLUGINS)
    # Plugins to build as COT blobs (Windows only, module-stomped at runtime).
    # All other plugins use the legacy DLL-LoadLibrary path.
    set(COT_PLUGINS
        evasion
        test
        eventlog
        timestomp
        services
        credstore
        netshare
        persist
        token
        getsystem
        kerberos
        inject
        forge
        ui
        clipboard
        registry
        uac
        arp
        wifi_passwords
        minidump
        smb_pipe
        schtasks
        sysinfo
        media
        credentials
        execute
        lsadump
        sniffer
    )

    file(GLOB PLUGIN_DIRS plugins/*)

    foreach(PLUGIN_DIR ${PLUGIN_DIRS})
        if(IS_DIRECTORY ${PLUGIN_DIR})
            get_filename_component(PLUGIN_NAME ${PLUGIN_DIR} NAME)
            file(GLOB PLUGIN_SOURCES ${PLUGIN_DIR}/*.c ${PLUGIN_DIR}/*.S)

            if(PLUGIN_SOURCES)
                if(CMAKE_SYSTEM_NAME STREQUAL Windows)
                    enable_language(ASM)

                    # Determine install paths
                    string(TOLOWER ${CMAKE_SYSTEM_NAME} TABS_PLATFORM)
                    set(TABS_ARCH ${CMAKE_SYSTEM_PROCESSOR})
                    set(TABS_DIR ${CMAKE_SOURCE_DIR}/pwny/tabs/${TABS_PLATFORM}/${TABS_ARCH})

                    if(PLUGIN_NAME IN_LIST COT_PLUGINS)
                        # -------------------------------------------
                        # COT build: compile as DLL, pe2cot -> .cot
                        # -------------------------------------------
                        add_library(plugin_${PLUGIN_NAME} SHARED
                            ${PLUGIN_SOURCES}
                        )
                        target_link_directories(plugin_${PLUGIN_NAME} PRIVATE
                            deps/build/${CMAKE_SYSTEM_TARGET}/lib)
                        # COT plugins don't call Pwny or Win32 APIs directly,
                        # but we still link tab_dll for the header dependencies
                        # and kernel32 for the minimal CRT startup stub.
                        target_link_libraries(plugin_${PLUGIN_NAME} PRIVATE tab_dll)
                        target_link_libraries(plugin_${PLUGIN_NAME} PRIVATE kernel32)
                        target_compile_options(plugin_${PLUGIN_NAME} PRIVATE
                            -Os -ffunction-sections -fdata-sections
                            -fno-stack-protector -fno-asynchronous-unwind-tables)
                        target_link_options(plugin_${PLUGIN_NAME} PRIVATE
                            -static-libgcc -Wl,--gc-sections -Wl,--strip-all
                            -Wl,--exclude-all-symbols)
                        set_target_properties(plugin_${PLUGIN_NAME} PROPERTIES
                            OUTPUT_NAME ${PLUGIN_NAME}
                            PREFIX ""
                            SUFFIX ".dll"
                            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
                            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins)

                        # Post-build: extract COT blob from the compiled DLL
                        add_custom_command(TARGET plugin_${PLUGIN_NAME} POST_BUILD
                            COMMAND ${CMAKE_COMMAND} -E make_directory ${TABS_DIR}
                            COMMAND python3 ${CMAKE_SOURCE_DIR}/scripts/pe2cot.py
                                $<TARGET_FILE:plugin_${PLUGIN_NAME}>
                                ${TABS_DIR}/${PLUGIN_NAME}
                            COMMENT "Converting plugin ${PLUGIN_NAME} to COT blob -> pwny/tabs/${TABS_PLATFORM}/${TABS_ARCH}/${PLUGIN_NAME}")

                    else()
                        # -------------------------------------------
                        # Legacy DLL build (loaded via LoadLibrary)
                        # -------------------------------------------
                        add_library(plugin_${PLUGIN_NAME} SHARED
                            ${PLUGIN_SOURCES}
                        )
                        target_link_directories(plugin_${PLUGIN_NAME} PRIVATE
                            deps/build/${CMAKE_SYSTEM_TARGET}/lib)
                        target_link_libraries(plugin_${PLUGIN_NAME} PRIVATE tab_dll)
                        target_link_libraries(plugin_${PLUGIN_NAME} PRIVATE
                            ws2_32 advapi32 netapi32 secur32 crypt32
                            ole32 oleaut32 avicap32 vfw32 winmm gdi32 user32)
                        target_compile_options(plugin_${PLUGIN_NAME} PRIVATE
                            -Os -ffunction-sections -fdata-sections)
                        target_link_options(plugin_${PLUGIN_NAME} PRIVATE
                            -static-libgcc -Wl,--gc-sections -Wl,--strip-all -Wl,--exclude-all-symbols)
                        set_target_properties(plugin_${PLUGIN_NAME} PROPERTIES
                            OUTPUT_NAME ${PLUGIN_NAME}
                            PREFIX ""
                            SUFFIX ".dll"
                            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
                            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins)

                        # Copy built plugin DLL to pwny/tabs/<platform>/<arch>/ for Python loader
                        add_custom_command(TARGET plugin_${PLUGIN_NAME} POST_BUILD
                            COMMAND ${CMAKE_COMMAND} -E make_directory ${TABS_DIR}
                            COMMAND ${CMAKE_COMMAND} -E copy
                                $<TARGET_FILE:plugin_${PLUGIN_NAME}>
                                ${TABS_DIR}/${PLUGIN_NAME}
                            COMMENT "Installing plugin ${PLUGIN_NAME} -> pwny/tabs/${TABS_PLATFORM}/${TABS_ARCH}/${PLUGIN_NAME}")
                    endif()
                else()
                    # POSIX: build plugins as executables with pipe IPC
                    add_executable(plugin_${PLUGIN_NAME} ${PLUGIN_SOURCES})
                    target_link_directories(plugin_${PLUGIN_NAME} PRIVATE
                        deps/build/${CMAKE_SYSTEM_TARGET}/lib)
                    target_link_libraries(plugin_${PLUGIN_NAME} PRIVATE tab ev)

                    if(CMAKE_SYSTEM_NAME STREQUAL Linux)
                        if(CMAKE_SYSTEM_PROCESSOR STREQUAL x64)
                            target_link_options(plugin_${PLUGIN_NAME} PRIVATE
                                -static-pie -Wl,-z,max-page-size=4096)
                        else()
                            target_link_options(plugin_${PLUGIN_NAME} PRIVATE -static-pie)
                        endif()
                    endif()

                    target_compile_options(plugin_${PLUGIN_NAME} PRIVATE
                        -Os -ffunction-sections -fdata-sections)
                    target_link_options(plugin_${PLUGIN_NAME} PRIVATE
                        -Wl,--gc-sections -Wl,--strip-all)
                    set_target_properties(plugin_${PLUGIN_NAME} PROPERTIES
                        OUTPUT_NAME ${PLUGIN_NAME}
                        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins)

                    # Copy built plugin to pwny/tabs/<platform>/<arch>/ for Python loader
                    string(TOLOWER ${CMAKE_SYSTEM_NAME} TABS_PLATFORM)
                    set(TABS_ARCH ${CMAKE_SYSTEM_PROCESSOR})
                    set(TABS_DIR ${CMAKE_SOURCE_DIR}/pwny/tabs/${TABS_PLATFORM}/${TABS_ARCH})
                    add_custom_command(TARGET plugin_${PLUGIN_NAME} POST_BUILD
                        COMMAND ${CMAKE_COMMAND} -E make_directory ${TABS_DIR}
                        COMMAND ${CMAKE_COMMAND} -E copy
                            $<TARGET_FILE:plugin_${PLUGIN_NAME}>
                            ${TABS_DIR}/${PLUGIN_NAME}
                        COMMENT "Installing plugin ${PLUGIN_NAME} -> pwny/tabs/${TABS_PLATFORM}/${TABS_ARCH}/${PLUGIN_NAME}")
                endif()
            endif()
        endif()
    endforeach()
endif()
