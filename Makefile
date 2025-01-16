CXX = g++
CXXFLAGS = -Wall -std=c++17 -I. -I./src

SRCDIR = src
BUILDDIR = build
BINDIR = bin
TARGET = airodump

# src/*.cpp 전체 탐색
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
# 소스 -> 오브젝트로 변경
OBJECTS = $(patsubst $(SRCDIR)/%.cpp, $(BUILDDIR)/%.o, $(SOURCES))

all: directories $(BINDIR)/$(TARGET)

# 빌드 디렉토리, 바이너리 디렉토리 생성
directories:
	mkdir -p $(BUILDDIR) $(BINDIR)

# 최종 실행 파일을 bin/ 폴더 안에 생성
$(BINDIR)/$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ -lpcap -lpthread

# 각 .cpp를 build/ 폴더 안의 .o로 빌드
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILDDIR) $(BINDIR)
