# Atajo rápido para Linux. Para Windows, o para un build más prolijo en
# Linux, usar CMakeLists.txt (cmake -B build && cmake --build build).
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I. -Isrc
LDFLAGS = -lssl -lcrypto -lpthread $(shell pkg-config --libs libseccomp)

SOURCES = main.cpp forensic.cpp utils.cpp \
          src/sandbox_linux.cpp src/seccomp_linux.cpp src/cgroups_linux.cpp
OBJ = $(SOURCES:.cpp=.o)

all: aegis-engine

aegis-engine: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f *.o src/*.o aegis-engine

.PHONY: all clean
