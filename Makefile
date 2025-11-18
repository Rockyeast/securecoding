.PHONY: all clean handin

CC=gcc
CFLAGS_COMMON=-O2 -g -Wall -Wextra -fno-omit-frame-pointer -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS_STOR=$(CFLAGS_COMMON) -Werror
CFLAGS_MALLOC=-w
LDFLAGS=-pie -Wl,-z,relro,-z,now
SODIUM_CFLAGS=$(shell pkg-config --cflags libsodium 2>/dev/null || echo "")
SODIUM_LIBS=$(shell pkg-config --libs libsodium 2>/dev/null || echo "-lsodium")

all: stor

stor: stor.o malloc-2.7.2.o
	$(CC) $(CFLAGS_COMMON) -o $@ $^ $(SODIUM_LIBS) $(LDFLAGS)

stor.o: stor.c
	$(CC) $(CFLAGS_STOR) $(SODIUM_CFLAGS) -c $< -o $@

malloc-2.7.2.o: malloc-2.7.2.c
	$(CC) $(CFLAGS_MALLOC) -c $< -o $@

clean:
	rm -vf stor handin.tar *.o

handin: clean
	tar -cf handin.tar --exclude=handin.tar $(SRC)
