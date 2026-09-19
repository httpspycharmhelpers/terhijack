CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
PREFIX  ?= /data/data/com.termux/files/usr

all: terhijack thj_patch thj_ptrace

terhijack: terhijack.c
	$(CC) $(CFLAGS) -o $@ $<

thj_patch: patch.c
	$(CC) $(CFLAGS) -o $@ $<

thj_ptrace: thj_ptrace.c
	$(CC) $(CFLAGS) -o $@ $<

install: all
	install -m 0755 terhijack $(PREFIX)/bin/terhijack
	install -m 0755 thj_patch $(PREFIX)/bin/thj_patch
	install -m 0755 thj_ptrace $(PREFIX)/bin/thj_ptrace

uninstall:
	rm -f $(PREFIX)/bin/terhijack $(PREFIX)/bin/thj_patch $(PREFIX)/bin/thj_ptrace

clean:
	rm -f terhijack thj_patch thj_ptrace

.PHONY: all install uninstall clean
