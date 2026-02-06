cmake_minimum_required(VERSION 3.10)

project(bbdd VERSION 0.1.0)

add_executable(
  bbdd
  bbdd.c
  bbdd-c.c
  bbdd-d.c
  bbdd-jrpc.c
  bbdd-sock.c
  )

target_link_libraries(bbdd json-c systemd)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -Wall -Wextra -Wshadow -Wpointer-arith -Wconversion -Wswitch-enum -Wpacked \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations")
