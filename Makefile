# Makefile for 1m-block.cpp

TARGET = 1m-block
SRC = 1m-block.cpp
CXX = g++
CXXFLAGS = -g -Wall
LIBS = -lnetfilter_queue

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

