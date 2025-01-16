#ifndef DOT11_TAGGED_PARAM_H
#define DOT11_TAGGED_PARAM_H

#include <cstdint>

/*
802.11 Management Frame 중 Beacon/Probe Response 등에 포함되는 Tagged Parameter(IE)들을 파싱하기 위한 간단한 구조(ESSID, DS Parameter, RSN 등).
*/

// 태그 번호 (Tag Number) 값들
static const uint8_t TAG_SSID          = 0x00;
static const uint8_t TAG_SUPPORTED_RATES = 0x01;
static const uint8_t TAG_DS_PARAMETER  = 0x03;
static const uint8_t TAG_RSN           = 0x30;
// ... 필요하면 추가

#pragma pack(push, 1)
struct Dot11TaggedParamHdr {
    uint8_t tagNumber;  // 태그 번호
    uint8_t tagLength;  // 태그 길이
    // 뒤에 tagLength만큼의 데이터가 이어짐
};
#pragma pack(pop)

#endif
