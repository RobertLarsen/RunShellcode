cmake_minimum_required(VERSION 3.5)
project(runshellcode)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")
add_executable(runshellcode src/runshellcode.c)
install(
    TARGETS runshellcode
    DESTINATION /usr/bin
)
