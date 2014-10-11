CC=g++
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=main.cpp utils.cpp TrustedObject.cpp UntrustedObject.cpp \
	VerificationObject.cpp Log.cpp LogEntry.cpp
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

