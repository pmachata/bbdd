cmake_minimum_required(VERSION 3.10)

project(bbdd VERSION 0.1.0)

add_executable(
  bbdd
  bbdd.c
  bbdd-bpf.c
  bbdd-c.c
  bbdd-d.c
  bbdd-jrpc.c
  bbdd-nl.c
  bbdd-sock.c
  )

target_link_libraries(bbdd json-c systemd mnl bpf)

find_program(CLANG clang REQUIRED)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bbdd.bpf.o
  COMMAND ${CLANG} -O2 -g -target bpf -c
          ${CMAKE_CURRENT_SOURCE_DIR}/bbdd.bpf.c
          -o ${CMAKE_CURRENT_BINARY_DIR}/bbdd.bpf.o
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bbdd.bpf.c
  VERBATIM)

add_custom_target(bbdd_bpf_prog
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/bbdd.bpf.o)

add_dependencies(bbdd bbdd_bpf_prog)

# xxx this won't work -- we need to fetch the object from
# a shared location. Leave it as is for now.
target_compile_definitions(bbdd PRIVATE
  BBDD_BPF_PROG_PATH="${CMAKE_CURRENT_BINARY_DIR}/bbdd.bpf.o")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -Wall -Wextra -Wshadow -Wpointer-arith -Wconversion -Wswitch-enum -Wpacked \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations")
