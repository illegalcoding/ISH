CFLAGS = -O0 -pipe -pthread -lm
all: ISH Parser
ISH: ISH.c
	$(CC) $(CFLAGS) ISH.c -o ish
Parser: Parser.c	
	$(CC) $(CFLAGS) -o parser Parser.c `pkg-config --cflags --libs json-c`
.PHONY: clean
clean:
	rm ish parser
