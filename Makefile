CFLAGS = -O0 -pipe -pthread -lm

all: ish

ish: main.o ish.o
    $(CC) $(CFLAGS) -o ish main.o inc.o

main.o: main.c ish.h
    $(CC) $(CFLAGS) -c main.c

inc.o: inc.c inc.h
    $(CC) $(CFLAGS) -c inc.c

.PHONY:clean
clean:
	rm ish *.o
