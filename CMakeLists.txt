cmake_minimum_required(VERSION 3.20)
project(callgraph VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(LIBDW REQUIRED IMPORTED_TARGET libdw)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
find_program(CLANG_EXECUTABLE NAMES clang REQUIRED)

include(ProcessorCount)
ProcessorCount(NPROC)
if(NPROC EQUAL 0)
  set(NPROC 4)
endif()

# ---------------------------------------------------------------------------
# Vendored libbpf (the distro package is too old for uprobe_multi).
# ---------------------------------------------------------------------------
set(LIBBPF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf)
set(LIBBPF_A ${LIBBPF_DIR}/src/libbpf.a)
set(LIBBPF_PREFIX ${CMAKE_BINARY_DIR}/libbpf-prefix)

# The libbpf source tree keeps its public headers at src/*.h while the
# installed layout is include/bpf/*.h.  Recreate that layout for both the
# host build and the BPF compile.
file(MAKE_DIRECTORY ${LIBBPF_PREFIX}/include/bpf)
file(MAKE_DIRECTORY ${LIBBPF_PREFIX}/include/linux)
foreach(header
    bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h bpf_helpers.h
    bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h
    skel_internal.h libbpf_version.h usdt.bpf.h)
  configure_file(${LIBBPF_DIR}/src/${header}
                 ${LIBBPF_PREFIX}/include/bpf/${header} COPYONLY)
endforeach()
foreach(header bpf.h bpf_common.h btf.h)
  configure_file(${LIBBPF_DIR}/include/uapi/linux/${header}
                 ${LIBBPF_PREFIX}/include/linux/${header} COPYONLY)
endforeach()

add_custom_command(
  OUTPUT ${LIBBPF_A}
  COMMAND ${CMAKE_MAKE_PROGRAM} -C ${LIBBPF_DIR}/src -j${NPROC} BUILD_STATIC_ONLY=1
  DEPENDS ${LIBBPF_DIR}/src/Makefile
  COMMENT "Building vendored libbpf"
  VERBATIM
)
add_custom_target(libbpf_build DEPENDS ${LIBBPF_A})

add_library(libbpf STATIC IMPORTED GLOBAL)
set_target_properties(libbpf PROPERTIES
  IMPORTED_LOCATION ${LIBBPF_A}
  INTERFACE_INCLUDE_DIRECTORIES "${LIBBPF_PREFIX}/include"
)
add_dependencies(libbpf libbpf_build)

# The BPF program captures x86-64 SysV argument registers.  On other
# architectures the fields remain zero and --args is rejected at runtime.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  set(BPF_ARCH_DEFINE -DCALLGRAPH_BPF_X86_64=1)
else()
  set(BPF_ARCH_DEFINE "")
endif()

# ---------------------------------------------------------------------------
# BPF program: compile and embed.
# ---------------------------------------------------------------------------
set(BPF_OBJ ${CMAKE_BINARY_DIR}/trace.bpf.o)
add_custom_command(
  OUTPUT ${BPF_OBJ}
  COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf
          ${BPF_ARCH_DEFINE}
          -I${LIBBPF_PREFIX}/include
          -I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
          -I${CMAKE_CURRENT_SOURCE_DIR}/bpf
          -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/trace.bpf.c
          -o ${BPF_OBJ}
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/trace.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/trace.h
  COMMENT "Compiling BPF program"
  VERBATIM
)

set(BPF_BLOB ${CMAKE_BINARY_DIR}/trace_bpf_blob.h)
add_custom_command(
  OUTPUT ${BPF_BLOB}
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bpf.sh
          ${BPF_OBJ} ${BPF_BLOB} bpf_trace_bpf_o
  DEPENDS ${BPF_OBJ} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bpf.sh
  COMMENT "Embedding BPF program"
  VERBATIM
)

# ---------------------------------------------------------------------------
# User-space tracer.
# ---------------------------------------------------------------------------
add_executable(callgraph
  src/main.cpp
  src/common.cpp
  src/elf_resolver.cpp
  src/dwarf_args.cpp
  src/arguments.cpp
  src/module_manager.cpp
  src/probe_manager.cpp
  src/call_stack.cpp
  src/output.cpp
  src/process_controller.cpp
  src/event_collector.cpp
  ${BPF_BLOB}
)

target_include_directories(callgraph PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/bpf
  ${CMAKE_BINARY_DIR}
)
target_compile_definitions(callgraph PRIVATE CALLGRAPH_VERSION="${PROJECT_VERSION}")
target_compile_options(callgraph PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(callgraph PRIVATE
  libbpf
  PkgConfig::LIBELF
  PkgConfig::LIBDW
  ZLIB::ZLIB
  Threads::Threads
)

# Optional: libopcodes is used to find `ret` instructions so that return
# probes can avoid uretprobes (which break C++ exception unwinding).
find_path(DIS_ASM_INCLUDE NAMES dis-asm.h)
find_library(OPCODES_LIBRARY NAMES opcodes)
if(DIS_ASM_INCLUDE AND OPCODES_LIBRARY)
  target_compile_definitions(callgraph PRIVATE CALLGRAPH_HAVE_LIBOPCODES=1)
  target_include_directories(callgraph PRIVATE ${DIS_ASM_INCLUDE})
  target_link_libraries(callgraph PRIVATE ${OPCODES_LIBRARY})
  message(STATUS "libopcodes found: --return-mode=ret enabled")
else()
  message(STATUS "libopcodes not found: --return-mode=ret unavailable")
endif()

add_dependencies(callgraph libbpf_build)

include(CTest)
if(BUILD_TESTING)
  add_executable(callgraph_tests
    tests/unit/test_main.cpp
    src/common.cpp
    src/arguments.cpp
    src/call_stack.cpp
    src/output.cpp
  )
  target_include_directories(callgraph_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf
  )
  target_compile_options(callgraph_tests PRIVATE -Wall -Wextra)
  target_link_libraries(callgraph_tests PRIVATE Threads::Threads)
  add_test(NAME unit COMMAND callgraph_tests)
  add_test(NAME integration
           COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.sh
                   $<TARGET_FILE:callgraph>)
  set_tests_properties(integration PROPERTIES TIMEOUT 180)
endif()

install(TARGETS callgraph RUNTIME DESTINATION bin)
