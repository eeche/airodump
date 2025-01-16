#ifndef AIRODUMP_STATION_INFO_H
#define AIRODUMP_STATION_INFO_H

#include <string>
#include <cstdint>
#include "MacAddr.h"

struct AirodumpStationInfo {
    MacAddr stationMac;    // 스테이션(클라이언트) MAC
    MacAddr connectedBssid; // 어느 AP와 연결?
    uint64_t dataCount = 0; // 전송 데이터 프레임 수

    AirodumpStationInfo() {}
};

#endif
