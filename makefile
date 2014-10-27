CC=g++ -std=c++0x
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=main.cpp utils.cpp TrustedObject.cpp UntrustedObject.cpp \
	VerificationObject.cpp Log.cpp LogEntry.cpp message.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=SecureAudit

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o
	rm SecureAudit

