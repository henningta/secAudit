CC=g++ -std=c++0x
CFLAGS=-c -Wall 
LDFLAGS= -lssl -lcrypto
SOURCES=main.cpp utils.cpp TrustedObject.cpp UntrustedObject.cpp \
	VerificationObject.cpp Log.cpp LogEntry.cpp message.cpp cryptsuite.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=SecureAudit

example: cryptsuite example.cpp
	$(CC) -o example example.cpp cryptsuite.o -lssl -lcrypto

cryptsuite: cryptsuite.cpp cryptsuite.hpp
	$(CC) $(CFLAGS) cryptsuite.cpp

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o
	rm SecureAudit

