CFLAGS = -O0 -pipe -std=c11 -ggdb -pthread -lm
all:
	egcc $(CFLAGS) scanner.c -o scanner
