#ifndef AIRODUMP_AP_INFO_H
#define AIRODUMP_AP_INFO_H

#include <string>
#include <cstdint>
#include "MacAddr.h"

struct AirodumpApInfo {
    MacAddr bssid;          // BSSID
    int pwr = 0;            // 신호 세기 (RSSI)
    uint64_t beaconCount = 0; // 받은 Beacon 개수
    uint64_t dataCount = 0;   // Data 개수
    std::string encryption; // "WEP", "WPA2", ...
    std::string essid;      // ESSID

    AirodumpApInfo() {}
};

#endif
