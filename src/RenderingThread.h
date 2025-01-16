#ifndef RENDERING_THREAD_H
#define RENDERING_THREAD_H

/*
실제 airodump-ng처럼 curses나 ncurses 기반으로 실시간 테이블을 예쁘게 렌더링하려면 별도 쓰레드가 필요
여기서는 간단히 주기적으로 AP/Station 목록을 콘솔에 찍는 역할을 main.cpp에서 수행한다고 가정
만약 별도 RenderingThread를 두고 싶다면 추가 구현 필요요
*/

class RenderingThread {
public:
    void start() {
        // std::thread 생성, AP/Station DB를 주기적으로 읽어 화면 업데이트
    }
    void stop() {
        // thread 종료
    }
};

#endif
