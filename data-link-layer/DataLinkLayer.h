//
// Created by 24599 on 2021/12/3.
//

#ifndef ZS_SENDER_DATALINKLAYER_H
#define ZS_SENDER_DATALINKLAYER_H

#define HAVE_REMOTE
// c++ header
#include<stdio.h>
#include<stdlib.h>
#include<cstring>
#include<cmath>
#include<iostream>
#include<queue>
#include<vector>
#include<stack>
#include<mutex>
#include<thread>
#include<unistd.h>
#include<direct.h>
// common
#include<macro.h>

// winpcap
#include<pcap.h>

typedef struct ethernet_header {
    u_int8_t dst_mac[MAC_BYTE_LENGTH];
    u_int8_t src_mac[MAC_BYTE_LENGTH];
    u_int16_t ethernet_type;
} Header;

typedef struct ethernet_packet {
    u_int8_t *packet;
    unsigned int packet_size;
} Packet;

class DataLinkLayer {
public:

    DataLinkLayer();

    /**
     *  ethernet stack callback
     * @param argument
     * @param packet_header
     * @param packet_content
     */
    friend void ethernet_callback(u_char *argument,
                                  const struct pcap_pkthdr *packet_header,
                                  const u_char *packet_content);

    void save_data();

    void write_to_file(Packet &buffer, unsigned int len);

    void run();

    void printer();

    ~DataLinkLayer();

private:
    std::queue<Packet> receive_queue_;
    pcap_if_t *all_devs_;
    pcap_if_t *dev_;
    pcap_t *dev_handle_;
    Header *header_data_;   //数据头
    struct pcap_pkthdr *detail_; //详细信息,packet_header
    uint8_t *data_;         //有效数据
    unsigned int len_;      //总长度
    unsigned int data_len_; //数据长度
    int dev_id_;
    int dev_nums_ = 0;
    std::mutex *tex_ = new std::mutex();
    char error_buffer_[PCAP_ERRBUF_SIZE];
    FILE *file_save_;

};


#endif //ZS_SENDER_DATALINKLAYER_H
