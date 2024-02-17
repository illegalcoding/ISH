CFLAGS = -O0 -pipe -pthread -lm
all: ish parser
ish: ish.c
	$(CC) $(CFLAGS) ish.c -o ish
parser: parser.c	
	$(CC) $(CFLAGS) -o parser parser.c `pkg-config --cflags --libs json-c`
.PHONY: clean
clean:
	rm ish parser
