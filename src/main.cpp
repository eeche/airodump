#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <csignal>
#include <chrono>
#include <pcap.h>
#include <cstring>
#include <vector>
#include <iomanip>

#include "MacAddr.h"
#include "AirodumpApInfo.h"
#include "AirodumpStationInfo.h"
#include "my_radiotap.h"
#include "Dot11.h"
#include "Dot11TaggedParam.h"

// 전역(혹은 싱글턴) 형태로 AP/Station DB, mutex 관리
static std::map<MacAddr, AirodumpApInfo> g_apDatabase;
static std::map<MacAddr, AirodumpStationInfo> g_stationDatabase;
static std::mutex g_dbMutex;

// 채널 호핑을 위한 인터페이스/스레드
static std::atomic<bool> g_running{false};
static std::thread g_hopperThread;

// pcap handle
static pcap_t* g_handle = nullptr;

// 종료 플래그
static bool g_terminate = false;
void signalHandler(int signo) {
    g_terminate = true;
}

// 채널 리스트
struct ChannelInfo {
    int channelNumber;
    int frequency;
};

static std::vector<ChannelInfo> g_channels = {
    {1, 2412}, {2, 2417}, {3, 2422}, {4, 2427}, {5, 2432},
    {6, 2437}, {7, 2442}, {8, 2447}, {9, 2452}, {10, 2457},
    {11, 2462},
};

// ----------------------------------------------------------------------------
// 채널 호핑 함수
// ----------------------------------------------------------------------------
void channelHopper(const std::string& interface) {
    size_t idx = 0;
    while (g_running) {
        std::string cmd = "iwconfig " + interface + " channel " + std::to_string(g_channels[idx].channelNumber);
        system(cmd.c_str());

        std::this_thread::sleep_for(std::chrono::seconds(1));
        idx = (idx + 1) % g_channels.size();
    }
}

// ----------------------------------------------------------------------------
// 실제 Beacon 프레임의 Tagged Parameter에서 ESSID/Encryption 추출
// ----------------------------------------------------------------------------
static void parseBeacon(const uint8_t* dot11Ptr, int dot11Len, int powerDbm) {
    // 1) Dot11 MAC 헤더
    const Dot11Hdr* dot11 = reinterpret_cast<const Dot11Hdr*>(dot11Ptr);
    size_t dot11HdrLen = sizeof(Dot11Hdr);
    if (dot11Len < (int)dot11HdrLen) return;

    // 2) 고정 파라미터(12바이트: Timestamp(8)+BeaconInterval(2)+Capability(2))
    const size_t fixedLen = 12;
    if (dot11Len < (int)(dot11HdrLen + fixedLen)) return;

    // BSSID
    MacAddr bssid(dot11->addr3);

    // 3) Tagged Parameter 시작 지점
    const uint8_t* tagPtr = dot11Ptr + dot11HdrLen + fixedLen;
    size_t remain = dot11Len - (dot11HdrLen + fixedLen);

    std::string essidStr = "(hidden)";
    std::string encStr = "OPEN";

    // 4) 태그 순회
    while (remain >= 2) {
        uint8_t tagNumber = tagPtr[0];
        uint8_t tagLength = tagPtr[1];
        if (remain < (size_t)(2 + tagLength)) {
            break; // 잘못된 태그 or 끝
        }

        const uint8_t* tagData = tagPtr + 2;

        if (tagNumber == 0) { 
            // SSID 태그
            if (tagLength > 0) {
                essidStr.assign(reinterpret_cast<const char*>(tagData), tagLength);
            } else {
                essidStr = "(hidden)";
            }
        } 
        else if (tagNumber == 0x30) {
            // RSN => WPA2
            encStr = "WPA2";
        }
        else if (tagNumber == 0xdd) {
            // Vendor Specific => WPA(가능성)
            // 실제로는 태그 내부 OUI(0x00 0x50 0xf2) 등을 검사
            encStr = "WPA";
        }

        tagPtr += (2 + tagLength);
        remain -= (2 + tagLength);
    }

    // 5) DB 업데이트
    {
        std::lock_guard<std::mutex> lock(g_dbMutex);

        AirodumpApInfo& ap = g_apDatabase[bssid];
        ap.bssid = bssid;
        ap.pwr = powerDbm;
        ap.beaconCount++;
        ap.essid = essidStr;       // 파싱한 ESSID
        ap.encryption = encStr;    // OPEN / WPA / WPA2
    }
}

// ----------------------------------------------------------------------------
// 패킷 핸들러
// ----------------------------------------------------------------------------
void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet) {
    int radiotapLen = 0;
    int powerDbm = 0;

    if (!parseRadiotap(packet, header->len, radiotapLen, powerDbm)) {
        return; // Radiotap 파싱 실패
    }

    // 802.11 헤더 시작점
    const u_char* dot11Ptr = packet + radiotapLen;
    int dot11Len = header->len - radiotapLen;
    if (dot11Len < (int)sizeof(Dot11Hdr)) {
        return; // 너무 짧음
    }

    const Dot11Hdr* dot11 = reinterpret_cast<const Dot11Hdr*>(dot11Ptr);
    uint16_t fc = dot11->frameControl;
    uint16_t fc_le = fc; // 엔디안 고려(간단히 fc 그대로 씀)

    if (isBeaconFrame(fc_le)) {
        // Beacon 프레임 파싱
        parseBeacon(dot11Ptr, dot11Len, powerDbm);
    } 
    else if (isDataFrame(fc_le)) {
        // Data 프레임: To DS / From DS 비트 확인
        uint8_t toDs   = (fc_le & 0x0100) >> 8;
        uint8_t fromDs = (fc_le & 0x0200) >> 9;

        MacAddr stationMac, bssidMac;
        // Infrastructure 모드: 
        //  - station -> AP => Addr1 = BSSID, Addr2 = Station
        //  - AP -> station => Addr1 = Station, Addr2 = BSSID
        if (!fromDs && toDs) {
            // station -> AP
            bssidMac   = MacAddr(dot11->addr1);
            stationMac = MacAddr(dot11->addr2);
        } else if (fromDs && !toDs) {
            // AP -> station
            stationMac = MacAddr(dot11->addr1);
            bssidMac   = MacAddr(dot11->addr2);
        } else {
            // ad-hoc, WDS 등은 간단 예시에선 스킵
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_dbMutex);

            // AP DB에 존재한다면 dataCount++
            auto it = g_apDatabase.find(bssidMac);
            if (it != g_apDatabase.end()) {
                it->second.dataCount++;
            }

            // Station DB 관리
            AirodumpStationInfo& stn = g_stationDatabase[stationMac];
            stn.stationMac = stationMac;
            stn.connectedBssid = bssidMac;
            stn.dataCount++;
        }
    }
    else {
        // Probe, RTS/CTS, 관리 프레임 등등...
        // 필요시 추가 파싱
    }
}

// ----------------------------------------------------------------------------
// main()
// ----------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "syntax : airodump <interface>\n"
                  << "sample : airodump mon0\n";
        return -1;
    }

    std::string interface = argv[1];

    // 시그널 핸들러
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // pcap_open_live
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    g_handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (g_handle == nullptr) {
        std::cerr << "pcap_open_live(" << interface << ") failed: " << errbuf << std::endl;
        return -1;
    }

    // Radiotap(802.11) 모니터링 체크
    if (pcap_datalink(g_handle) != DLT_IEEE802_11_RADIO) {
        std::cerr << "[-] Not a radiotap header capture. Try setting monitor mode on interface.\n";
        pcap_close(g_handle);
        return -1;
    }

    // 채널 호핑
    g_running = true;
    g_hopperThread = std::thread(channelHopper, interface);

    // pcap_loop
    std::thread captureThread([&]() {
        pcap_loop(g_handle, 0, packetHandler, nullptr);
    });

    // 메인 스레드: 주기적으로 AP/Station 정보 출력
    while (!g_terminate) {
        {
            std::lock_guard<std::mutex> lock(g_dbMutex);

#ifdef _WIN32
            system("cls");
#else
            system("clear");
#endif
            // ----------------- AP List -----------------
            std::cout << "\n===== AP List =====\n";
            std::cout
                << std::left  << std::setw(20) << "BSSID"
                << std::left  << std::setw(6)  << "PWR"
                << std::left  << std::setw(9)  << "Beacons"
                << std::left  << std::setw(7)  << "#Data"
                << std::left  << std::setw(6)  << "ENC"
                << std::left  << std::setw(15) << "ESSID"
                << "\n";
            std::cout << "------------------------------------------------------\n";

            for (auto& kv : g_apDatabase) {
                const AirodumpApInfo& ap = kv.second;
                std::cout 
                    << std::left << std::setw(20) << (std::string)ap.bssid
                    << std::left << std::setw(6)  << (std::to_string(ap.pwr) + "dBm")
                    << std::left << std::setw(9)  << ap.beaconCount
                    << std::left << std::setw(7)  << ap.dataCount
                    << std::left << std::setw(6)  << ap.encryption
                    << std::left << std::setw(15) << ap.essid
                    << "\n";
            }

            // ----------------- Station List -----------------
            std::cout << "\n===== Station List =====\n";
            std::cout 
                << std::left << std::setw(20) << "Station"
                << std::left << std::setw(20) << "BSSID"
                << std::left << "#Data"
                << "\n";
            std::cout << "------------------------------------------------------\n";

            for (auto& kv : g_stationDatabase) {
                const AirodumpStationInfo& st = kv.second;
                std::cout
                    << std::left << std::setw(20) << (std::string)st.stationMac
                    << std::left << std::setw(20) << (std::string)st.connectedBssid
                    << st.dataCount
                    << "\n";
            }
            std::cout << "------------------------------------------------------\n";
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    // 종료 루틴
    g_running = false;
    if (g_handle) {
        pcap_breakloop(g_handle);
    }
    if (captureThread.joinable())
        captureThread.join();
    if (g_hopperThread.joinable())
        g_hopperThread.join();
    if (g_handle) {
        pcap_close(g_handle);
        g_handle = nullptr;
    }

    return 0;
}
