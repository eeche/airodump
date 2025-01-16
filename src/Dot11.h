#ifndef DOT11_H
#define DOT11_H

#include <cstdint>

/*
802.11 MAC 헤더 파싱용 구조체, 매직 넘버 최소화하기

참고:
Frame Control(2byte)
Duration/ID(2byte)
Addr1(6byte)
Addr2(6byte)
Addr3(6byte)
Sequence Control(2byte)
Addr4(6byte) (있을 수도 있음)
*/

#pragma pack(push, 1)
struct Dot11Hdr {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seqCtrl;
    // Addr4(6bytes)는 존재할 수도 있지만, Beacon은 3개의 Addr를 주로 사용
};
#pragma pack(pop)

// Beacon인 경우 frameControl = 0x80(= type=0, subtype=8)
inline bool isBeaconFrame(uint16_t fc) {
    // FC의 subtype이 8, type이 0이면 Beacon
    // frameControl(16bit)에서 하위 4bit = subtype, 그 윗 2bit = type
    // frameControl & 0x00F0 = subtype << 4
    // frameControl & 0x000C = type << 2
    uint8_t subType = (fc & 0x00F0) >> 4;
    uint8_t type    = (fc & 0x000C) >> 2;
    return (type == 0 && subType == 8);
}

inline bool isDataFrame(uint16_t fc) {
    // Data frame => type=2
    // subtype은 다양(0, 8, 12 등)
    uint8_t type = (fc & 0x000C) >> 2;
    return (type == 2);
}

#endif
