# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

KEYING = keying 
UTILS = utils

all: keying

keying: keying.o utils.o

keying.o: keying.c utils.h
	$(CC) $(CFLAGS) -o keying.o -c keying.c 

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -o utils.o -c utils.c 

clean:
	rm -f utils.o keying.o keying