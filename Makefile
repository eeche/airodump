CXX = g++
CXXFLAGS = -Wall -std=c++17 -I. -I./src

SRCDIR = src
OBJS = $(SRCDIR)/AirodumpApInfo.o \
       $(SRCDIR)/AirodumpStationInfo.o \
       $(SRCDIR)/MacAddr.o \
       $(SRCDIR)/my_radiotap.o \
       $(SRCDIR)/main.o

TARGET = airodump

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ -lpcap -lpthread

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
