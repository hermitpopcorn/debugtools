CC ?= cc
CPPFLAGS += $(shell pkg-config --cflags openssl)
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O0 -g
LDLIBS += $(shell pkg-config --libs openssl)

.PHONY: all keys clean

all: receiver sender

receiver: receiver.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS)

sender: sender.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS)

keys:
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
	openssl pkey -in private.pem -pubout -out public.pem

clean:
	rm -f receiver sender private.pem public.pem output.txt
