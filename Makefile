CFLAGS = -std=c99 -O2 -pipe -pthread -lm `pkg-config --cflags --libs json-c openssl`
all: ISH Parser
ISH: ISH.c SSL.c Shared.c Request.c
	$(CC) $(CFLAGS) ISH.c SSL.c Shared.c Request.c -o ish
Parser: Parser.c Shared.c	
	$(CC) $(CFLAGS) -o parser Shared.c Parser.c
.PHONY: clean
clean:
	rm ish parser
