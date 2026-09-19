CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
PREFIX  ?= /data/data/com.termux/files/usr

all: terhijack thj_patch

terhijack: terhijack.c
	$(CC) $(CFLAGS) -o $@ $<

thj_patch: patch.c
	$(CC) $(CFLAGS) -o $@ $<

install: all
	install -m 0755 terhijack $(PREFIX)/bin/terhijack
	install -m 0755 thj_patch $(PREFIX)/bin/thj_patch

uninstall:
	rm -f $(PREFIX)/bin/terhijack $(PREFIX)/bin/thj_patch

clean:
	rm -f terhijack thj_patch

.PHONY: all install uninstall clean
