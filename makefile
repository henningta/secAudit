CC=g++ -std=c++0x
CFLAGS=-c -Wall 
LDFLAGS= -lssl -lcrypto
SOURCES=main.cpp utils.cpp TrustedObject.cpp UntrustedObject.cpp \
	VerificationObject.cpp Log.cpp LogEntry.cpp message.cpp cryptsuite.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=SecureAudit

all: crypto $(SOURCES) $(EXECUTABLE)

crypto: 
	$(CC) $(CFLAGS) $(LDFLAGS) cryptsuite.cpp

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o
	rm SecureAudit

