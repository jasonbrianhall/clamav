CC = g++
CFLAGS = -std=c++17 -Wall -Wextra
LDFLAGS = -lclamav -lboost_filesystem -lboost_system -pthread
TARGET = virus_scanner
SRC = clamav.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install:
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

test: $(TARGET)
	./$(TARGET) --help
	
# Run a simple scan on the current directory
scan: $(TARGET)
	./$(TARGET) .

# Run a recursive scan with quarantine enabled
scan-recursive: $(TARGET)
	./$(TARGET) -r -q .

# Generate a text report
report-txt: $(TARGET)
	./$(TARGET) -r --report-txt scan_report.txt .

# Generate a CSV report
report-csv: $(TARGET)
	./$(TARGET) -r --report-csv scan_report.csv .
