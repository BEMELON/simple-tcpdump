CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET1 = simple_tcpdump
TARGET2 = bpf_tcpdump
SOURCE1 = simple_tcpdump.c
SOURCE2 = bpf_tcpdump.c

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(SOURCE1)
	$(CC) $(CFLAGS) -o $(TARGET1) $(SOURCE1)

$(TARGET2): $(SOURCE2)
	$(CC) $(CFLAGS) -o $(TARGET2) $(SOURCE2)

clean:
	rm -f $(TARGET1) $(TARGET2)

install: $(TARGET1) $(TARGET2)
	sudo cp $(TARGET1) /usr/local/bin/
	sudo cp $(TARGET2) /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET1)
	sudo rm -f /usr/local/bin/$(TARGET2)

.PHONY: all clean install uninstall