cmake_minimum_required(VERSION 3.20)
project(zs_receiver)

set(CMAKE_CXX_STANDARD 14)

set(WINPCAP_INCLUDE_DIR D:/WpdPack/Include)
set(WINPCAP_LIBRARIES D:/WpdPack/Lib/x64)

include_directories(${WINPCAP_INCLUDE_DIR})
link_directories(${WINPCAP_LIBRARIES})

include_directories(data-link-layer)
include_directories(common)

add_subdirectory(common)
add_subdirectory(data-link-layer)

# message(STATUS Packet wpcap)
add_executable(zs_receiver main.cpp)

target_link_libraries(zs_receiver ReceiverDataLink Packet wpcap)