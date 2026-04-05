cmake_minimum_required(VERSION 3.15)
project(libload C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(APPLE)
    enable_language(OBJC)
else()
    enable_language(ASM)
endif()

# Compiler flags
add_compile_options(-Wall -Wextra -Werror -O2)

option(LIBLOAD_DEBUG "Enable debug logging to stderr" OFF)
if(LIBLOAD_DEBUG)
    add_compile_definitions(LIBLOAD_DEBUG)
endif()

# ─── Platform source selection ────────────────────────────────────
if(APPLE)
    set(LIBLOAD_SRC src/macho.c src/inject.c)
elseif(UNIX)
    set(LIBLOAD_SRC src/elf.c src/elf_inject.c
                    src/entry_x86_64.S src/entry_aarch64.S
                    src/entry_x86.S src/entry_arm.S
                    src/entry_mips.S src/entry_sparc.S)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# ─── Shared library ──────────────────────────────────────────────
add_library(libload_shared SHARED ${LIBLOAD_SRC})
target_include_directories(libload_shared PUBLIC include)
set_target_properties(libload_shared PROPERTIES OUTPUT_NAME load)

if(UNIX AND NOT APPLE)
    target_link_libraries(libload_shared PRIVATE dl)
endif()

# ─── Static library ──────────────────────────────────────────────
add_library(libload_static STATIC ${LIBLOAD_SRC})
target_include_directories(libload_static PUBLIC include)
set_target_properties(libload_static PROPERTIES OUTPUT_NAME load)

# ─── llpack tool ─────────────────────────────────────────────────
add_executable(llpack tools/llpack.c)
target_include_directories(llpack PRIVATE include)

# ─── Common examples ─────────────────────────────────────────────
add_executable(testexec examples/common/testexec.c)
add_executable(testexec_edge examples/common/testexec_edge.c)

add_executable(test_exec examples/common/test_exec.c)
target_link_libraries(test_exec PRIVATE libload_static)

add_executable(test_llbin examples/common/test_llbin.c)
target_link_libraries(test_llbin PRIVATE libload_static)

add_executable(test_open examples/common/test_open.c)
target_link_libraries(test_open PRIVATE libload_static)

add_executable(inject_target examples/common/inject_target.c)

add_library(inject_payload SHARED examples/common/inject_payload.c)

add_library(test_lib SHARED examples/common/test_lib.c)

# ─── Install ─────────────────────────────────────────────────────
install(TARGETS libload_shared libload_static llpack
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)

# ─── macOS examples ──────────────────────────────────────────────
if(APPLE)
    set_target_properties(inject_payload PROPERTIES
        PREFIX "" SUFFIX ".dylib" OUTPUT_NAME "inject_payload")
    set_target_properties(test_lib PROPERTIES
        PREFIX "" SUFFIX ".dylib" OUTPUT_NAME "test_lib")

    add_executable(testexec_objc examples/macos/testexec_objc.m)
    target_link_libraries(testexec_objc PRIVATE objc)
    target_compile_options(testexec_objc PRIVATE -Wno-unused-parameter)

    add_executable(testexec_objc_class examples/macos/testexec_objc_class.m)
    target_link_libraries(testexec_objc_class PRIVATE objc)
    target_compile_options(testexec_objc_class PRIVATE -Wno-unused-parameter)

    add_executable(testexec_tlv examples/macos/testexec_tlv.c)

    add_executable(test_inject examples/macos/test_inject.c)
    target_link_libraries(test_inject PRIVATE libload_static)

    add_executable(test_inject_dylib examples/macos/test_inject_dylib.c)
    target_link_libraries(test_inject_dylib PRIVATE libload_static)

    add_executable(test_inject_spawn examples/macos/test_inject_spawn.c)
    target_link_libraries(test_inject_spawn PRIVATE libload_static)
endif()

# ─── Linux examples ──────────────────────────────────────────────
if(UNIX AND NOT APPLE)
    set_target_properties(inject_payload PROPERTIES
        PREFIX "" SUFFIX ".so" OUTPUT_NAME "inject_payload")
    set_target_properties(test_lib PROPERTIES
        PREFIX "" SUFFIX ".so" OUTPUT_NAME "test_lib")

    add_executable(test_inject examples/linux/test_inject.c)
    target_link_libraries(test_inject PRIVATE libload_static)

    add_executable(test_inject_dylib examples/linux/test_inject_dylib.c)
    target_link_libraries(test_inject_dylib PRIVATE libload_static dl)

    add_executable(test_inject_spawn examples/linux/test_inject_spawn.c)
    target_link_libraries(test_inject_spawn PRIVATE libload_static)

    add_executable(test_bin examples/linux/test_bin.c)
    target_compile_options(test_bin PRIVATE -Wno-unused-parameter)

    # Architecture-specific assembly bin loaders
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        add_executable(test_bin_asm
            examples/linux/test_bin_aarch64.S)
        target_link_options(test_bin_asm PRIVATE -nostdlib -static)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
        add_executable(test_bin_asm
            examples/linux/test_bin_x86_64.S)
        target_link_options(test_bin_asm PRIVATE -nostdlib -static)
    endif()
endif()
