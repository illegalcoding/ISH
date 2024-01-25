CFLAGS = -fdiagnostics-color -O2 -pipe -std=c11 -ggdb -pthread -lm
all:
	$(CC) $(CFLAGS) ish.c -o ish
	$(CC) $(CFLAGS) -o parser parser.c `pkg-config --cflags --libs json-c`
