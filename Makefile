CC ?= cc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -O2

.PHONY: all test clean

all: main rijndael.so

rijndael.o: rijndael.c rijndael.h
	$(CC) $(CFLAGS) -o rijndael.o -fPIC -c rijndael.c

main: rijndael.o main.c
	$(CC) $(CFLAGS) -o main main.c rijndael.o

rijndael.so: rijndael.o
	$(CC) -o rijndael.so -shared rijndael.o

test_aes: test_aes.c rijndael.o rijndael.h
	$(CC) $(CFLAGS) -o test_aes test_aes.c rijndael.o

test: rijndael.so test_aes
	./test_aes
	python3 -m pytest test_rijndael.py -v

clean:
	rm -f *.o *.so
	rm -f main test_aes
