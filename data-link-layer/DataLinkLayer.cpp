//
// Created by 24599 on 2021/12/3.
//

#include "DataLinkLayer.h"

#include "functional"

uint8_t src_mac[MAC_BYTE_LENGTH] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
uint8_t dst_mac[MAC_BYTE_LENGTH] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
uint8_t broadcast_mac[MAC_BYTE_LENGTH] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

//std::mutex tex_;
void ethernet_callback(u_char *argument, const struct pcap_pkthdr *packet_header,
                       const u_char *packet_content) {
    printf("enter callback!\n");
    auto pthis = (DataLinkLayer *) argument;
    pthis->detail_ = (struct pcap_pkthdr *) packet_header;
    pthis->len_ = packet_header->len;
    pthis->header_data_ = (Header *) packet_content;
    pthis->data_ = (uint8_t *) (packet_content + sizeof(Header));
//    printf("len is %u",pthis->len_);

    for (int i = 0; i < MAC_BYTE_LENGTH; i++) {
        if (pthis->header_data_->dst_mac[i] != broadcast_mac[i]) {
            break;
        }
        if (i == MAC_BYTE_LENGTH - 1) {
            printf("This is a broadcast!!!\n");
            // handle broadcast
        }
    }
    for (int i = 0; i < MAC_BYTE_LENGTH; i++) {
        if (pthis->header_data_->dst_mac[i] != src_mac[i]) {
            printf("dest mac address is not match!\n");
            return;
        }
    }

    for (int i = 0; i < MAC_BYTE_LENGTH; i++) {
        if (pthis->header_data_->src_mac[i] != src_mac[i]) {
            printf("src mac address is not match!\n");
            return;
        }
    }


    pthis->data_len_ = pthis->len_ - 4 - sizeof(Header);
    if (pthis->data_len_ < 46 || pthis->data_len_ > 1500) {
        printf("数据长度为： %d，不符合要求\n\n", pthis->data_len_);
        return;
    }

    auto pack = (u_int8_t *) packet_content;

    while (pthis->receive_queue_.size() > QUEUE_MAX_SIZE) {
        printf("recv queue full!");
    }


    pthis->tex_->lock();
    Packet packet = {pack, pthis->len_};
    pthis->receive_queue_.push(packet);
    pthis->tex_->unlock();
    Sleep(SLEEP_TIME);

    pthis->printer();


}

DataLinkLayer::DataLinkLayer() {

    printf("dev list is here: \n");
    if (pcap_findalldevs_ex((char *) PCAP_SRC_IF_STRING, nullptr, &all_devs_, error_buffer_) == -1) {
        fprintf(stderr, "Error in findalldevs_ex function: %s\n", error_buffer_);
        exit(-1);
    }

    if (all_devs_ == nullptr) {
        printf("\nNo adapters found! Make sure WinPcap is installed!!!\n");
        exit(-1);
    }

    for (dev_ = all_devs_; dev_ != nullptr; dev_ = dev_->next) {
        printf("\n%d.%s\n", ++dev_nums_, dev_->name);
        printf("--- %s\n", dev_->description);
    }
    printf("\n");

    printf("Enter the adapter id between 1 and %d: ", dev_nums_);
    scanf("%d", &dev_id_);
    if (dev_id_ < 1 || dev_id_ > dev_nums_) {
        printf("\n Adapter id out of range.\n");
        pcap_freealldevs(all_devs_);
        exit(-1);
    }

    dev_ = all_devs_;
    for (int i = 1; i < dev_id_; i++) {
        dev_ = dev_->next;
    }
    dev_handle_ = pcap_open(dev_->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 5, nullptr, error_buffer_);//打开网卡的句柄

    if (dev_handle_ == nullptr) {
        fprintf(stderr, "\n Unable to open adapter: %s\n", dev_->name);
        pcap_freealldevs(all_devs_);
        exit(-1);
    }
}

void DataLinkLayer::save_data() {
    int times = 0;
    while (times < MAX_DELAY) {
        times = 0;
        while (receive_queue_.empty()) {
            printf("recv queue is empty!\n");
            times++;
            Sleep(SLEEP_TIME);
            if (times > MAX_DELAY) return;
        }
        tex_->lock();

        Packet packet = receive_queue_.front();
        receive_queue_.pop();

        tex_->unlock();
        unsigned int datalen = packet.packet_size - sizeof(ethernet_header) - 4;

        write_to_file(packet, datalen);
//        std::ofstream outfile;
//        outfile.open("test.txt", std::ios::out | std::ios::app);
//        for (int i = 0; i < datalen; i++) {
//            outfile << *(buffer_start + i);
//        }
//        outfile.close();
        //fflush(file_save_);
        //fseek(file_save_, -1, SEEK_CUR);
    }
    //fclose(recvfile);
}

void DataLinkLayer::run() {

    std::thread save_thread([this]() -> auto { this->save_data(); });
    save_thread.detach();
    pcap_loop(dev_handle_, 0, ethernet_callback, (uint8_t *)this);

}


DataLinkLayer::~DataLinkLayer() {
    pcap_close(dev_handle_);
    pcap_freealldevs(all_devs_);
}

void DataLinkLayer::printer() {

    static int packet_num = 1;

    printf("enter printer!\n");

    printf("----------------------------\n");
    printf("capture %d packet\n", packet_num);//数据帧序号
    printf("capture time: %ld\n", detail_->ts.tv_sec);//数据帧接受时间
    printf("packet length: %d\n", detail_->len);//数据帧总长度
    printf("packet header length: %I64u\n", sizeof(ethernet_header));//数据帧报头长度
    printf("packet data length: %u\n", data_len_);//数据帧数据部分长度
    printf("-----Ethernet protocol-------\n");
    printf("Ethernet type: %04x\n", header_data_->ethernet_type);//%04x 表示按16进制输出数据，最小输出宽度为4个字符，右对齐，如果输出的数据小于4个字符，前补0
    uint8_t *src_mac_ = header_data_->src_mac;
    printf("MAC source address: %02x:%02x:%02x:%02x:%02x:%02x\n", *src_mac_, *(src_mac_ + 1), *(src_mac_ + 2),
           *(src_mac_ + 3),
           *(src_mac_ + 4), *(src_mac_ + 5));
    uint8_t *dst_mac_ = header_data_->dst_mac;
    printf("MAC destination address: %02x:%02x:%02x:%02x:%02x:%02x\n", *dst_mac_, *(dst_mac_ + 1), *(dst_mac_ + 2),
           *(dst_mac_ + 3), *(dst_mac_ + 4), *(dst_mac_ + 5));

    //printf("补零的个数：%c", (*(char*)(packet_content + packet_header->len - 5)));//最后一个字节一定是补0的个数

    //fprintf(recvfile, "\n");
    //printf("\n");
    //printf("----------------------\n");

    packet_num++;
}

void DataLinkLayer::write_to_file(Packet &packet, unsigned int len) {
    file_save_ = fopen("../test.txt", "rb+");
    if (file_save_ != nullptr) {
        auto buffer_start = (u_int8_t *) (packet.packet + sizeof(ethernet_header));
        fwrite(buffer_start, sizeof(u_int8_t), len, file_save_);
        for (auto p = (u_int8_t *) (packet.packet + sizeof(ethernet_header));
             p != (u_int8_t *) (packet.packet + packet.packet_size - 4); p++) {
            //printf("%c", char(*p));//每次读入一个字节
            fprintf(file_save_, "%c", *p);
        }
    }
    fclose(file_save_);
    printf("\nsave file successful! \n");
}