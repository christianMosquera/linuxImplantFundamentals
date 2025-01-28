# Compiler and flags
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap
DEPS = utils.h

# Target executable
TARGET = sniffer

# Source files
SRC = sniffer.c

# Object files
OBJ = sniffer.o utils.o

all: sniffer

sniffer: sniffer.o utils.o 
	$(CC) -o sniffer sniffer.o utils.o $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
