CC = gcc
CFLAGS = -Wall -Wextra -lpcap

sniffex: sniffex.c
	$(CC) $(CFLAGS) -o sniffex sniffex.c

valgrind: sniffex
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./sniffex