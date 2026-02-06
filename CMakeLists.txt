cmake_minimum_required(VERSION 3.10)

project(bbdd VERSION 0.1.0)

# Software based BFD data plane.
add_executable(
  bbdd
  bbdd-sock.c
  )

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -Wall -Wextra -Wshadow -Wpointer-arith -Wconversion -Wswitch-enum -Wpacked \
  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations")
