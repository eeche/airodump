#include "my_radiotap.h"
#include <iostream>

/*
간단한 Radiotap 파서: 
앞부분 구조체(RadiotapHdr)를 읽고 length만 반영
나머지(파워 dBm)는 presentFlags나 이후 필드 해석 필요
예시로 특정 field가 있다고 가정하고 -50dBm 같은 값을 넣어봄
 
실제로는 radiotap.org를 참고하거나, 무선 헤더 문서를 참고해 present flag 별로 오프셋을 찾아 해석
*/

bool parseRadiotap(const uint8_t* packet, int packetLen, int& radiotapLen, int& powerDbm) {
    if (packetLen < (int)sizeof(RadiotapHdr)) {
        std::cerr << "[!] Packet too short for Radiotap\n";
        return false;
    }

    const RadiotapHdr* hdr = reinterpret_cast<const RadiotapHdr*>(packet);

    radiotapLen = hdr->length; // 전체 Radiotap 헤더 길이
    if (radiotapLen > packetLen) {
        std::cerr << "[!] Radiotap length invalid\n";
        return false;
    }

    // 신호 강도(powerDbm)은 예시로 -50으로 고정 (실제는 hdr->presentFlags를 검사 후 파싱)
    powerDbm = -50;
    return true;
}
