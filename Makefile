CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
PREFIX  ?= /data/data/com.termux/files/usr

all: terhijack

terhijack: terhijack.c
	$(CC) $(CFLAGS) -o $@ $<

install: terhijack
	install -m 0755 terhijack $(PREFIX)/bin/terhijack

uninstall:
	rm -f $(PREFIX)/bin/terhijack

clean:
	rm -f terhijack

.PHONY: all install uninstall clean
