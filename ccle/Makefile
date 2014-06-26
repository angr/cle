LIB:=$(CURDIR)
DESTDIR=$(VIRTUAL_ENV)/opt/

all: libcle-x86_64 libcle-mips libcle-ppc libcle_ctypes-x86_64 clextract-x86_64 clextract-mips clextract-ppc

libcle-x86_64: libcle.c
	mkdir -p x86_64
	x86_64-linux-gnu-gcc -Wall -c -fpic libcle.c -o x86_64/libcle.o
	x86_64-linux-gnu-gcc -shared x86_64/libcle.o -o x86_64/libcle.so

libcle-mips: libcle.c
	mkdir -p mips
	mips-linux-gnu-gcc -Wall -c -fpic libcle.c -o mips/libcle.o
	mips-linux-gnu-gcc -shared mips/libcle.o -o mips/libcle.so

libcle-ppc: libcle.c
	mkdir -p ppc
	powerpc-linux-gnu-gcc -Wall -c -fpic libcle.c -o ppc/libcle.o
	powerpc-linux-gnu-gcc -shared ppc/libcle.o -o ppc/libcle.so
	
libcle_ctypes-x86_64: libcle_ctypes.c
	x86_64-linux-gnu-gcc -Wall -c -fpic libcle_ctypes.c -o x86_64/libcle_ctypes.o
	x86_64-linux-gnu-gcc -shared x86_64/libcle_ctypes.o x86_64/libcle.o -o x86_64/libcle_ctypes.so

clextract-x86_64: clextract.c
	x86_64-linux-gnu-gcc -c clextract.c -o x86_64/clextract.o
	x86_64-linux-gnu-gcc -L$(LIB)/x86_64 -Wall x86_64/clextract.o -o x86_64/clextract -lcle

clextract-mips: clextract.c
	mips-linux-gnu-gcc -c clextract.c -o mips/clextract.o
	mips-linux-gnu-gcc -L$(LIB)/mips -Wall mips/clextract.o -o mips/clextract -lcle

clextract-ppc: clextract.c
	powerpc-linux-gnu-gcc -c clextract.c -o ppc/clextract.o
	powerpc-linux-gnu-gcc -L$(LIB)/ppc -Wall ppc/clextract.o -o ppc/clextract -lcle


install:
	mkdir -p $(DESTDIR)
	cp -a x86_64 mips ppc $(DESTDIR)


clean:
	 rm -f x86_64/*.so *.o clextract 
	 rm -f arm/*.so arm/*.o arm/clextract 
	 rm -f mips/*.so mips/*.o mips/clextract 
	 rm -f ppc/*.so arm/*.o arm/clextract 
