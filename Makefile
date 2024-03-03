CFLAGS = -O0 -pipe -pthread -lm -lssl -lcrypto
all: ISH Parser
ISH: ISH.c
	$(CC) $(CFLAGS) ISH.c SSL.c Shared.c Request.c -o ish
Parser: Parser.c	
	$(CC) $(CFLAGS) -o parser Shared.c Parser.c `pkg-config --cflags --libs json-c`
.PHONY: clean
clean:
	rm ish parser
