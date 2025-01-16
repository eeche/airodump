#ifndef MAC_ADDR_H
#define MAC_ADDR_H

#include <iostream>
#include <cstdint>
#include <cstring>
#include <iomanip>

#pragma pack(push, 1)
class MacAddr final {
public:
    static const size_t LENGTH = 6;
    static const uint8_t BROADCAST[LENGTH];

private:
    uint8_t addr[LENGTH] = {0,};

public:
    MacAddr() {}
    MacAddr(const uint8_t *target) { memcpy(this->addr, target, LENGTH); }

    // 형 변환
    operator uint8_t*() { return addr; }
    operator const uint8_t*() const { return addr; }

    // 대입 연산
    void operator=(const uint8_t* target) { memcpy(this->addr, target, LENGTH); }

    // 비교 연산
    bool operator==(const MacAddr& target) const { return memcmp(this->addr, target.addr, LENGTH) == 0; }
    bool operator!=(const MacAddr& target) const { return !(*this == target); }
    bool operator< (const MacAddr& target) const { return (memcmp(this->addr, target.addr, LENGTH) < 0); }

    // 문자열 변환
    operator std::string() const {
        char buf[18];
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        return std::string(buf);
    }

    // 스트림 출력 연산자
    friend std::ostream& operator<<(std::ostream& os, const MacAddr& obj) {
        os << std::hex << std::setfill('0')
           << std::setw(2) << (unsigned)obj.addr[0] << ":"
           << std::setw(2) << (unsigned)obj.addr[1] << ":"
           << std::setw(2) << (unsigned)obj.addr[2] << ":"
           << std::setw(2) << (unsigned)obj.addr[3] << ":"
           << std::setw(2) << (unsigned)obj.addr[4] << ":"
           << std::setw(2) << (unsigned)obj.addr[5]
           << std::dec << std::setfill(' ');
        return os;
    }
};
#pragma pack(pop)

#endif
