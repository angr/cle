DESTDIR=$(VIRTUAL_ENV)/lib
cflags = -Wall -fstack-protector
cc = gcc $(cflags)

# We only want libbfd-multiarch, otherwise it won't work with anything else
# than binaries compiled for the host system. Make sure you apt-get install
# libbfd-multiarch and libbfd-multiarch-dev first !


all: cle_bfd.so

cle_bfd.so: cle_bfd.c
	$(cc) -c -fpic cle_bfd.c -o cle_bfd.o
	$(cc) -shared cle_bfd.o -o cle_bfd.so -lbfd-multiarch

test: cle_bfd.c test.c
	gcc -shared cle_bfd.o -o libcle_bfd.so -lbfd-multiarch
	gcc -Wall -L$(PWD) test.c -o test -lcle_bfd

.PHONY: install clean
install: 
	cp cle_bfd.so $(DESTDIR)

clean:
	rm -f *.o *.so test

