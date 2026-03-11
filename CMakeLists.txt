cmake_minimum_required(VERSION 3.10)

project(bbdd VERSION 0.1.0)

include(GNUInstallDirs)

set(BBDD_DEFAULT_SOCKDIR "${CMAKE_INSTALL_FULL_RUNSTATEDIR}")
configure_file(config.h.in config.h)

add_executable(
  bbdd
  bbdd.c
  bbdd-bpf.c
  bbdd-c.c
  bbdd-d.c
  bbdd-jrpc.c
  bbdd-nl.c
  bbdd-sess.c
  bbdd-sock.c
  )

target_link_libraries(bbdd json-c systemd mnl bpf)
target_include_directories(bbdd PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

find_program(CLANG clang REQUIRED)
find_program(BPFTOOL bpftool REQUIRED)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
  COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c
          > ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
  VERBATIM)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bbdd-prog.bpf.o
  COMMAND ${CLANG} -O2 -g -target bpf
          -I${CMAKE_CURRENT_BINARY_DIR}
          -c ${CMAKE_CURRENT_SOURCE_DIR}/bbdd-prog.bpf.c
          -o ${CMAKE_CURRENT_BINARY_DIR}/bbdd-prog.bpf.o
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bbdd-prog.bpf.c
          ${CMAKE_CURRENT_SOURCE_DIR}/bbdd-prog.h
          ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
  VERBATIM)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bbdd-prog.skel.h
  COMMAND sh -c "${BPFTOOL} gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/bbdd-prog.bpf.o name bbdd_prog > ${CMAKE_CURRENT_BINARY_DIR}/bbdd-prog.skel.h"
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/bbdd-prog.bpf.o
  VERBATIM)

add_custom_target(bbdd_bpf_prog
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/bbdd-prog.skel.h)

add_dependencies(bbdd bbdd_bpf_prog)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -Wall -Wextra -Wshadow -Wpointer-arith -Wconversion -Wswitch-enum -Wpacked \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations")
