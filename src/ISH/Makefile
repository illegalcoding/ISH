CFLAGS = -O0 -pipe -pthread -lm
all: ish
ish: main.c ish.o ish.h
	$(CC) $(CFLAGS) ish.o main.c -o ish
.PHONY:clean
clean:
	rm ish *.o
