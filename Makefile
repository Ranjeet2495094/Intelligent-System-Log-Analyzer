CXX = g++
CXXFLAGS = -std=c++98 -Wall -Wextra -pedantic
INCLUDE_DIR = include
SRC_DIR = src
OBJ = src/LogEntry.o src/LogParser.o src/LogAnalyzer.o src/ReportGenerator.o src/BackupManager.o src/LogGuardManager.o src/main.o
TARGET = logguard

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -o $(TARGET) $(OBJ)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
