cmake_minimum_required(VERSION 3.20)
project(zs_receiver)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fexec-charset=GBK")

set(WINPCAP_INCLUDE_DIR D:/WpdPack/Include)
set(WINPCAP_LIBRARIES D:/WpdPack/Lib/x64)

include_directories(${WINPCAP_INCLUDE_DIR})
link_directories(${WINPCAP_LIBRARIES})

# message(STATUS Packet wpcap)
add_executable(zs_receiver main.cpp)

target_link_libraries(zs_receiver Packet wpcap)


