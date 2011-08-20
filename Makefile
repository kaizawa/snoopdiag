CC = gcc
PRODUCTS = snoopdiag 

all: $(PRODUCTS)

clean:
	rm -f snoopdiag

snoopdiag: snoopdiag.c
	$(CC) snoopdiag.c -D_BSD_SOURCE -g -o snoopdiag -lnsl
