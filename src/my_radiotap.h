#ifndef MY_RADIOTAP_H
#define MY_RADIOTAP_H

#include <cstdint>

/*
Radiotap 헤더를 구조체로 파싱하기 위한 정의
실제로는 다양한 필드(bitmask)와 가변 길이가 존재하므로, 간단히 전체 길이와 dBm 신호 강도만 추출
*/

#pragma pack(push, 1)
struct RadiotapHdr {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t presentFlags; 
    // 그 뒤로 여러 필드가 가변적으로 이어짐
};
#pragma pack(pop)

/*
실제 Radiotap Parsing 로직을 구현하는 함수
radiotap 헤더의 length를 이용해 전체 길이를 얻고 present flags를 체크하여 신호 강도 필드(dBm) 오프셋을 찾는 식
*/
bool parseRadiotap(const uint8_t* packet, int packetLen, int& radiotapLen, int& powerDbm);

#endif
