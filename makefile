# authors Jackson Reed, Travis Henning, Timothy Thong

CC=g++ -std=c++0x
CFLAGS=-c -Wall -g
LDFLAGS= -lssl -lcrypto
SOURCES=main.cpp utils.cpp TrustedObject.cpp UntrustedObject.cpp \
	VerificationObject.cpp Log.cpp LogEntry.cpp Message.cpp cryptsuite.cpp \
	debug.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=SecureAudit

all: $(SOURCES) $(EXECUTABLE)

example: cryptsuite example.cpp debug
	$(CC) -o example example.cpp debug.o cryptsuite.o -lssl -lcrypto

cryptsuite: cryptsuite.cpp cryptsuite.hpp
	$(CC) $(CFLAGS) cryptsuite.cpp

debug: debug.cpp debug.hpp
	$(CC) $(CFLAGS) debug.cpp

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o
	rm SecureAudit
	rm example

