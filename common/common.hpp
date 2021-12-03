//
// Created by 24599 on 2021/12/2.
//

#ifndef ZS_SENDER_COMMON_HPP
#define ZS_SENDER_COMMON_HPP

u_int32_t crc32_table[256];

class SenderToolbox {
public:
    SenderToolbox() {}

    //generate table
    void generate_crc32_table() {
        int i, j;
        uint32_t crc;
        for (i = 0; i < 256; i++) {
            crc = i;
            for (j = 0; j < 8; j++) {
                if (crc & 1)
                    crc = (crc >> 1) ^ 0xEDB88320;
                else
                    crc >>= 1;
            }
            crc32_table[i] = crc;
        }
    }

    uint32_t calculate_crc(u_int8_t *buffer, int len) {
        int i;
        uint32_t crc;
        crc = 0xffffffff;
        for (i = 0; i < len; i++) {
            crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
        }
        crc ^= 0xffffffff;
        return crc;
    }

};

#endif //ZS_SENDER_COMMON_HPP
