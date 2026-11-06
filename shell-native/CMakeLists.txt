cmake_minimum_required(VERSION 3.22)
project(rscoders_shell LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(rscoders SHARED src/rscoders_shell.cpp)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(rscoders ${log-lib} ${android-lib} z)

target_link_options(rscoders PRIVATE $<$<CONFIG:Release>:-s>)