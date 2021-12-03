cmake_minimum_required(VERSION 3.20)

project(receiver_data_link)

set(CMAKE_CXX_STANDARD 14)

set(WINPCAP_LIBRARIES D:/WpdPack/Lib/x64)

link_directories(${WINPCAP_LIBRARIES})

add_library(ReceiverDataLink STATIC DataLinkLayer.cpp)

target_link_libraries(ReceiverDataLink Packet wpcap)

