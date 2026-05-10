CXX := g++
CXXFLAGS := -O2 -Wall -Wextra -std=c++17
LDFLAGS := -lz

TARGET := copygrail
SRC := copygrail.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -static -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
