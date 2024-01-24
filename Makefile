CFLAGS = -O2 -pipe -std=c11 -ggdb -pthread -lm
all:
	$(CC) $(CFLAGS) scanner.c -o scanner
	$(CC) $(CFLAGS) -o parser parser.c `pkg-config --cflags --libs json-c`
