#include  <stdio.h>
#include  <stdlib.h>

#define HAVE_REMOTE
#include<pcap.h>
#include<WinSock2.h>

// c++ header
#include<cstring>
#include<cmath>
#include<iostream>
#include<queue>
#include<vector>
#include<stack>
#include<mutex>
#include<thread>
#include<fstream>

#define ETHERNET_TYPE 0x0800 //ipv4
#define MAX_SIZE 1530
#define DATA_MAX_SIZE 1400
#define MAC_BYTE_LENGTH 6
#define QUEUE_MAX_SIZE 100
#define SLEEP_TIME 100
#define MAX_DELAY 200

// #pragma warning(disable:4996)

FILE* recvfile = fopen("..\\test.txt", "ab+");

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void save_data();
int timeout_count = 0;

//以太帧帧头格式
struct ethernet_header
{
    u_int8_t ether_dhost[MAC_BYTE_LENGTH];//目的mac地址
    u_int8_t ether_shost[MAC_BYTE_LENGTH];//源mac地址
    u_int16_t ether_type;//协议类型
};

u_int8_t accept_dst_mac[2][MAC_BYTE_LENGTH] = { { 0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B }, { 0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B } };
u_int8_t accept_src_mac[2][MAC_BYTE_LENGTH] = { { 0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B }, { 0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B } };
u_int32_t crc32_table[256];

struct ethernet_packet
{
    u_int8_t* packet;
    int packet_size;
};

std::queue<ethernet_packet> recv_queue;
std::mutex tex;

void save_data() {
    while (timeout_count < MAX_DELAY) {
        timeout_count = 0;
        while (recv_queue.empty()) {
            printf("recv queue is empty!\n");
            timeout_count++;
            Sleep(SLEEP_TIME);
            if (timeout_count > MAX_DELAY) return;
        }
        tex.lock();

        ethernet_packet packet = recv_queue.front();
        recv_queue.pop();

        tex.unlock();
        int datalen = packet.packet_size - sizeof(ethernet_header) - 4;
        // u_int8_t* p;
        u_int8_t* buffer_start = (u_int8_t*)(packet.packet + sizeof(ethernet_header));
        std::ofstream outfile;
        outfile.open("test.txt", std::ios::out | std::ios::app);
        for (int i = 0; i < datalen; i++) {
            outfile << *(buffer_start + i);
        }
        outfile.close();
        //if (recvfile != NULL)
        //{
        //	u_int8_t* buffer_start = (u_int8_t*)(packet.packet + sizeof(ethernet_header));
        //	fwrite(buffer_start, sizeof(u_int8_t), datalen, recvfile);
        //for (p = (u_int8_t*)(packet.packet + sizeof(ethernet_header)); p != (u_int8_t*)(packet.packet + packet.packet_size - 4); p++)
        //{
        //	//printf("%c", char(*p));//每次读入一个字节
        //	fprintf(recvfile, "%c", *p);
        //}
        //}
        //fflush(recvfile);
        //fseek(recvfile, -1, SEEK_CUR);
        printf("\nsave file successful! \n");
    }
    fclose(recvfile);
}
void generate_crc32_table()//动态生成CRC32的码表
{
    int i, j;
    u_int32_t crc;//产生32位的冗余校验码
    for (i = 0; i < 256; i++)
    {
        crc = i;
        for (j = 0; j < 8; j++)
        {
            if (crc & 1)//与操作
                crc = (crc >> 1) ^ 0xEDB88320; //完成两个数据的按位异或操作
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
}

u_int32_t calculate_crc(u_int8_t* buffer, int len)
{
    int i;
    u_int32_t crc;
    crc = 0xffffffff;
    for (i = 0; i < len; i++)
    {
        crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
    }
    crc ^= 0xffffffff;
    return crc;
}


void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)//数据接收回调函数
{
    //packet_content的类型是char,说明数据是按照字节进行计算的
    u_short ethernet_type;//协议类型
    struct ethernet_header* ethernet_protocol;//帧头部
    u_char* mac_string;//保存MAC地址，利用指针
    static int packet_number = 1;
    ethernet_protocol = (struct ethernet_header*)packet_content;//强制类型转换，取了14个字节
    int len = packet_header->len;//数据包的实际长度
    int i, j;

    int flag = 2;
    for (i = 0; i < 2; i++)
    {
        flag = 2;
        for (j = 0; j < 6; j++)
        {
            if (ethernet_protocol->ether_dhost[j] == accept_dst_mac[i][j])//数据包帧的目的地址是否相同
                continue;
            else
            {
                flag = i;
                break;
            }
        }
        if (flag != 2)
            continue;
        else
        {
            break;
        }
    }
    if (flag != 2)
    {
        printf("目的地址不匹配\n");
        return;

    }

    //if (i == 0)
    //{
    //	printf("广播地址\n");
    //}

    // if the source is acceptable
    for (int i = 0; i < 2; i++)
    {
        flag = 1;
        for (j = 0; j < 6; j++)
        {
            if (ethernet_protocol->ether_shost[j] == accept_src_mac[i][j])
                continue;
            else
            {
                flag = 0;
                break;
            }
        }
        if (flag)
            break;
    }
    if (flag != 1)
    {
        printf("源地址不匹配\n");
        return;
    }

    //see if the data is changed or not
    u_int32_t crc = calculate_crc((u_int8_t*)(packet_content + sizeof(ethernet_header)), len - 4 - sizeof(ethernet_header));
    if (crc != *((u_int32_t*)(packet_content + len - 4)))
    {
        printf("The data has been changed.\n");
        return;
    }

    // length check
    int datalen = len - 4 - sizeof(ethernet_header);
    if (datalen < 46 || datalen>1500)
    {
        printf("数据长度为： %d，不符合要求\n\n", datalen);
        return;
    }

    u_int8_t* pack = (u_int8_t*)packet_content;

    while (recv_queue.size() > QUEUE_MAX_SIZE) {
        printf("recv queue full!");
    }

    tex.lock();
    ethernet_packet packet = { pack, len};
    recv_queue.push(packet);
    tex.unlock();
    Sleep(SLEEP_TIME);



    printf("----------------------------\n");
    printf("capture %d packet\n", packet_number);//数据帧序号
    printf("capture time: %ld\n", packet_header->ts.tv_sec);//数据帧接受时间
    printf("packet length: %d\n", packet_header->len);//数据帧总长度
    printf("packet header length: %I64u\n", sizeof(ethernet_header));//数据帧报头长度
    printf("packet data length: %I64u\n", len - 4 - sizeof(ethernet_header));//数据帧数据部分长度
    printf("-----Ethernet protocol-------\n");
    ethernet_type = ethernet_protocol->ether_type;
    printf("Ethernet type: %04x\n", ethernet_type);//%04x 表示按16进制输出数据，最小输出宽度为4个字符，右对齐，如果输出的数据小于4个字符，前补0

    mac_string = ethernet_protocol->ether_shost;
    printf("MAC source address: %02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3),
           *(mac_string + 4), *(mac_string + 5));
    mac_string = ethernet_protocol->ether_dhost;
    printf("MAC destination address: %02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2),
           *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
    printf("补零的个数：%c", (*(char*)(packet_content + packet_header->len - 5)));//最后一个字节一定是补0的个数

    fprintf(recvfile, "\n");
    printf("\n");
    printf("----------------------\n");
    packet_number++;
    //system("pause");
}


int main()
{
    generate_crc32_table();

    pcap_if_t* all_adapters;//网卡设备列表
    pcap_if_t* adapter;
    pcap_t* adapter_handle;//捕捉实例的句柄
    char error_buffer[PCAP_ERRBUF_SIZE];
    printf("本机中mac地址列表如下：\n");
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &all_adapters, error_buffer) == -1)
    {
        fprintf(stderr, "Error in findalldevs_ex function: %s\n", error_buffer);
        return -1;
    }

    if (all_adapters == NULL)
    {
        printf("\nNo adapters found! Make sure WinPcap is installed!!!\n");
        return 0;
    }

    int id = 1;
    for (adapter = all_adapters; adapter != NULL; adapter = adapter->next)
    {
        printf("\n%d.%s\n", id++, adapter->name);
        printf("--- %s\n", adapter->description);
    }
    printf("\n");

    int adapter_id;
    printf("Enter the adapter id between 1 and %d: ", id - 1);
    scanf("%d", &adapter_id);
    if (adapter_id<1 || adapter_id>id - 1)
    {
        printf("\n Adapter id out of range.\n");
        pcap_freealldevs(all_adapters);
        return -1;
    }

    adapter = all_adapters;
    for (id = 1; id < adapter_id; id++)
    {
        adapter = adapter->next;
    }
    adapter_handle = pcap_open(adapter->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 5, NULL, error_buffer);//打开网卡的句柄

    if (adapter_handle == NULL)
    {
        fprintf(stderr, "\n Unable to open adapter: %s\n", adapter->name);
        pcap_freealldevs(all_adapters);
        return -1;
    }
    std::thread save_thread(save_data);
    save_thread.detach();
    pcap_loop(adapter_handle, 0, ethernet_protocol_packet_callback, NULL);

    pcap_close(adapter_handle);
    pcap_freealldevs(all_adapters);
    return 0;
}
