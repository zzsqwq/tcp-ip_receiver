cmake_minimum_required(VERSION 3.20)

project(common)

set(CMAKE_CXX_STANDARD 14)

add_library(receiver_toolbox INTERFACE common.hpp)

set_target_properties(receiver_toolbox PROPERTIES LINKER_LANGUAGE CXX)


