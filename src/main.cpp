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

struct ChannelInfo {
    int channelNumber;
    int frequency;
};

static std::vector<ChannelInfo> g_channels = {
    {1, 2412}, {2, 2417}, {3, 2422}, {4, 2427}, {5, 2432},
    {6, 2437}, {7, 2442}, {8, 2447}, {9, 2452}, {10, 2457},
    {11, 2462},
};

void channelHopper(const std::string& interface) {
    size_t idx = 0;
    while (g_running) {
        std::string cmd = "iwconfig " + interface + " channel " + std::to_string(g_channels[idx].channelNumber);
        system(cmd.c_str());

        // 1초 정도 대기 후 다음 채널
        std::this_thread::sleep_for(std::chrono::seconds(1));
        idx = (idx + 1) % g_channels.size();
    }
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet) {
    int radiotapLen = 0;
    int powerDbm = 0;

    if (!parseRadiotap(packet, header->len, radiotapLen, powerDbm)) {
        // Radiotap 파싱 실패
        return;
    }

    // 802.11 헤더 시작점
    const u_char* dot11Ptr = packet + radiotapLen;
    int dot11Len = header->len - radiotapLen;
    if (dot11Len < (int)sizeof(Dot11Hdr)) {
        return; // 너무 짧음
    }

    const Dot11Hdr* dot11 = reinterpret_cast<const Dot11Hdr*>(dot11Ptr);
    uint16_t fc = dot11->frameControl;

    // 엔디안 이슈 있으므로 호스트 바이트 오더로 변환
    uint16_t fc_le = fc;

    if (isBeaconFrame(fc_le)) {
        // Beacon -> BSSID = addr3
        MacAddr bssid(dot11->addr3);

        // Beacon count 증가 등
        std::lock_guard<std::mutex> lock(g_dbMutex);
        AirodumpApInfo& ap = g_apDatabase[bssid];
        ap.bssid = bssid;
        ap.pwr = powerDbm;
        ap.beaconCount++;

        // ESSID, Encryption 추출 -> Tagged Parameter 파싱 필요
        // 여기서는 간단히 "UnknownESSID", "WPA2" 가정
        ap.essid = "UnknownESSID";
        ap.encryption = "WPA2";

    } else if (isDataFrame(fc_le)) {
        // 데이터 프레임: addr2 = Station, addr1 = AP(BSSID) or vice versa
        // QoS, from/to DS 플래그 등 구분 필요
        // 여기서는 간단히 addr2를 Station으로, addr1를 BSSID로 가정

        MacAddr stationMac(dot11->addr2);
        MacAddr maybeBssid(dot11->addr1);

        std::lock_guard<std::mutex> lock(g_dbMutex);

        // AP DB에 존재한다면 dataCount++
        auto it = g_apDatabase.find(maybeBssid);
        if (it != g_apDatabase.end()) {
            it->second.dataCount++;
        }

        // Station DB 관리
        AirodumpStationInfo& stn = g_stationDatabase[stationMac];
        stn.stationMac = stationMac;
        stn.connectedBssid = maybeBssid;
        stn.dataCount++;
    } else {
        // Probe, RTS/CTS, 관리 프레임 등등...
        // 필요시 추가 파싱
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "syntax : airodump <interface>\n"
                  << "sample : airodump mon0\n";
        return -1;
    }

    std::string interface = argv[1];

    // 시그널 핸들러 등록
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

    // Radiotap(802.11 모니터링)을 위해 링크 타입 확인
    if (pcap_datalink(g_handle) != DLT_IEEE802_11_RADIO) {
        std::cerr << "[-] Not a radiotap header capture. Try setting monitor mode on interface.\n";
        pcap_close(g_handle);
        return -1;
    }

    // 채널 호핑 시작
    g_running = true;
    g_hopperThread = std::thread(channelHopper, interface);

    // pcap_loop
    std::thread captureThread([&]() {
        pcap_loop(g_handle, 0, packetHandler, nullptr);
    });

    // 메인 스레드는 주기적으로 AP/Station 정보를 출력
    while (!g_terminate) {
        {
            std::lock_guard<std::mutex> lock(g_dbMutex);

            std::cout << "\n===== AP List =====\n";
            std::cout << "BSSID              PWR   Beacons  #Data  ENC   ESSID\n";
            std::cout << "------------------------------------------------------\n";
            for (auto& kv : g_apDatabase) {
                const AirodumpApInfo& ap = kv.second;
                std::cout << ap.bssid << "  "
                          << ap.pwr << "dBm  "
                          << ap.beaconCount << "       "
                          << ap.dataCount << "      "
                          << ap.encryption << "   "
                          << ap.essid << "\n";
            }

            std::cout << "\n===== Station List =====\n";
            std::cout << "Station            BSSID             #Data\n";
            std::cout << "------------------------------------------------------\n";
            for (auto& kv : g_stationDatabase) {
                const AirodumpStationInfo& st = kv.second;
                std::cout << st.stationMac << "  "
                          << st.connectedBssid << "  "
                          << st.dataCount << "\n";
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
