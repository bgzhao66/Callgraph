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
find_package(CURL QUIET)
find_package(Protobuf QUIET)
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
# architectures the fields remain zero and --show-args is rejected at runtime.
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
# Kernel-event BPF program: separate object so it is loaded only for
# --sched/--futex/--io/--block and cannot break the function tracer.
# ---------------------------------------------------------------------------
set(KERNEL_BPF_OBJ ${CMAKE_BINARY_DIR}/kernel.bpf.o)
add_custom_command(
  OUTPUT ${KERNEL_BPF_OBJ}
  COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf
          ${BPF_ARCH_DEFINE}
          -I${LIBBPF_PREFIX}/include
          -I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
          -I${CMAKE_CURRENT_SOURCE_DIR}/bpf
          -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kernel/trace.bpf.c
          -o ${KERNEL_BPF_OBJ}
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kernel/trace.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kernel_event.h
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kernel/common.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kernel/sched.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kernel/syscall.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/kernel/block.bpf.h
  COMMENT "Compiling kernel-event BPF program"
  VERBATIM
)

set(KERNEL_BPF_BLOB ${CMAKE_BINARY_DIR}/kernel_bpf_blob.h)
add_custom_command(
  OUTPUT ${KERNEL_BPF_BLOB}
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bpf.sh
          ${KERNEL_BPF_OBJ} ${KERNEL_BPF_BLOB} bpf_kernel_bpf_o
  DEPENDS ${KERNEL_BPF_OBJ} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_bpf.sh
  COMMENT "Embedding kernel-event BPF program"
  VERBATIM
)

# ---------------------------------------------------------------------------
# User-space tracer.
# ---------------------------------------------------------------------------
# OTLP protobuf messages.  gRPC and OTLP/HTTP+protobuf use the generated
# classes; without protobuf, OTLP/HTTP+JSON remains available.
set(CALLGRAPH_HAVE_OTLP_PROTO OFF)
set(OTLP_PROTO_SRCS "")
if(Protobuf_FOUND AND Protobuf_PROTOC_EXECUTABLE)
  set(OTLP_PROTO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/opentelemetry-proto)
  set(OTLP_PROTO_REL
    opentelemetry/proto/common/v1/common.proto
    opentelemetry/proto/resource/v1/resource.proto
    opentelemetry/proto/trace/v1/trace.proto
    opentelemetry/proto/collector/trace/v1/trace_service.proto
  )
  set(OTLP_PROTO_SRCS
    ${CMAKE_CURRENT_BINARY_DIR}/opentelemetry/proto/common/v1/common.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/opentelemetry/proto/resource/v1/resource.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/opentelemetry/proto/trace/v1/trace.pb.cc
    ${CMAKE_CURRENT_BINARY_DIR}/opentelemetry/proto/collector/trace/v1/trace_service.pb.cc
  )
  set(OTLP_PROTO_DEPS "")
  foreach(rel ${OTLP_PROTO_REL})
    list(APPEND OTLP_PROTO_DEPS ${OTLP_PROTO_ROOT}/${rel})
  endforeach()
  add_custom_command(
    OUTPUT ${OTLP_PROTO_SRCS}
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
            --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
            -I${OTLP_PROTO_ROOT}
            ${OTLP_PROTO_REL}
    DEPENDS ${OTLP_PROTO_DEPS}
    WORKING_DIRECTORY ${OTLP_PROTO_ROOT}
    COMMENT "Generating OTLP protobuf messages"
    VERBATIM
  )
  set(CALLGRAPH_HAVE_OTLP_PROTO ON)
  message(STATUS "protobuf found: OTLP gRPC and HTTP/protobuf enabled")
else()
  message(STATUS "protobuf/protoc not found: OTLP gRPC and HTTP/protobuf unavailable")
endif()

add_executable(callgraph
  src/main.cpp
  src/common.cpp
  src/elf_resolver.cpp
  src/dwarf_args.cpp
  src/arguments.cpp
  src/module_manager.cpp
  src/probe_manager.cpp
  src/kernel_probe_manager.cpp
  src/call_stack.cpp
  src/kernel_event.cpp
  src/kernel_timeline.cpp
  src/latency_stats.cpp
  src/histogram_report.cpp
  src/output.cpp
  src/process_controller.cpp
  src/event_collector.cpp
  src/clock_converter.cpp
  src/span_context.cpp
  src/span_generator.cpp
  src/otlp_json.cpp
  src/otlp_proto.cpp
  src/otel_exporter.cpp
  src/trace_parser.cpp
  src/trace_metadata.cpp
  src/flame_graph.cpp
  ${OTLP_PROTO_SRCS}
  ${BPF_BLOB}
  ${KERNEL_BPF_BLOB}
)

target_include_directories(callgraph PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/bpf
  ${CMAKE_BINARY_DIR}
  ${OTLP_PROTO_ROOT}
)
target_compile_definitions(callgraph PRIVATE CALLGRAPH_VERSION="${PROJECT_VERSION}")
if(CALLGRAPH_HAVE_OTLP_PROTO)
  target_compile_definitions(callgraph PRIVATE CALLGRAPH_HAVE_OTLP_PROTO=1)
  target_link_libraries(callgraph PRIVATE protobuf::libprotobuf)
endif()
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

# Optional: OTLP network export.  --exporter otlp-json works without curl.
if(CURL_FOUND)
  target_compile_definitions(callgraph PRIVATE CALLGRAPH_HAVE_CURL=1)
  target_link_libraries(callgraph PRIVATE CURL::libcurl)
  message(STATUS "libcurl found: OTLP network export enabled")
else()
  message(STATUS "libcurl not found: OTLP network export unavailable")
endif()

add_dependencies(callgraph libbpf_build)

include(CTest)
if(BUILD_TESTING)
  add_executable(callgraph_tests
    tests/unit/test_main.cpp
    src/common.cpp
    src/arguments.cpp
    src/call_stack.cpp
    src/kernel_event.cpp
    src/kernel_timeline.cpp
    src/latency_stats.cpp
    src/histogram_report.cpp
    src/output.cpp
    src/clock_converter.cpp
    src/span_context.cpp
    src/span_generator.cpp
    src/otlp_json.cpp
    src/otlp_proto.cpp
    src/otel_exporter.cpp
    src/trace_parser.cpp
    src/trace_metadata.cpp
    src/flame_graph.cpp
    ${OTLP_PROTO_SRCS}
  )
  target_include_directories(callgraph_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf
    ${CMAKE_CURRENT_BINARY_DIR}
    ${OTLP_PROTO_ROOT}
  )
  target_compile_definitions(callgraph_tests PRIVATE
    CALLGRAPH_VERSION="${PROJECT_VERSION}")
  if(CALLGRAPH_HAVE_OTLP_PROTO)
    target_compile_definitions(callgraph_tests PRIVATE CALLGRAPH_HAVE_OTLP_PROTO=1)
    target_link_libraries(callgraph_tests PRIVATE protobuf::libprotobuf)
  endif()
  target_compile_options(callgraph_tests PRIVATE -Wall -Wextra)
  target_link_libraries(callgraph_tests PRIVATE Threads::Threads ZLIB::ZLIB)
  if(CURL_FOUND)
    target_compile_definitions(callgraph_tests PRIVATE CALLGRAPH_HAVE_CURL=1)
    target_link_libraries(callgraph_tests PRIVATE CURL::libcurl)
  endif()
  add_test(NAME unit COMMAND callgraph_tests)
  add_test(NAME integration
           COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.sh
                   $<TARGET_FILE:callgraph>)
  set_tests_properties(integration PROPERTIES TIMEOUT 180)
endif()

install(TARGETS callgraph RUNTIME DESTINATION bin)
