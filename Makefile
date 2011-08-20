CC = gcc
PRODUCTS = snoopdiag 
ECHO = /bin/echo
CP = /bin/cp
RM = /bin/rm
LD = /usr/ucb/ld
RM = /bin/rm
CAT = /bin/cat

all: $(PRODUCTS)

clean:
	rm -f snoopdiag

snoopdiag: snoopdiag.c
	$(CC) snoopdiag.c -D_BSD_SOURCE -g -o snoopdiag -lnsl
