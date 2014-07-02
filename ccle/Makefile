LIB:=$(CURDIR)
BINDIR=$(VIRTUAL_ENV)/local/bin
LIBDIR=$(VIRTUAL_ENV)/local/lib

all:	libcle-mips clextract-mips \
		libcle-ppc clextract-ppc \
		libcle-x86_64 libcle_ctypes-x86_64 clextract-x86_64 clextract-x86_64 \
		libcle-arm clextract-arm \
		libcle-i386 clextract-i386

libcle-x86_64: libcle.c
	mkdir -p x86_64
	x86_64-linux-gnu-gcc -Wall -c -fpic libcle.c -o x86_64/libcle.o
	x86_64-linux-gnu-gcc -shared x86_64/libcle.o -o x86_64/libcle.so

libcle-i386: libcle.c
	mkdir -p i386
	x86_64-linux-gnu-gcc -m32 -Wall -c -fpic libcle.c -o i386/libcle.o
	x86_64-linux-gnu-gcc -m32 -shared i386/libcle.o -o i386/libcle.so

libcle-mips: libcle.c
	mkdir -p mips
	mips-linux-gnu-gcc -Wall -c -fpic libcle.c -o mips/libcle.o
	mips-linux-gnu-gcc -shared mips/libcle.o -o mips/libcle.so

libcle-ppc: libcle.c
	mkdir -p ppc
	powerpc-linux-gnu-gcc -Wall -c -fpic libcle.c -o ppc/libcle.o
	powerpc-linux-gnu-gcc -shared ppc/libcle.o -o ppc/libcle.so

libcle-arm: libcle.c
	mkdir -p arm
	arm-linux-gnueabi-gcc -Wall -c -fpic libcle.c -o arm/libcle.o
	arm-linux-gnueabi-gcc -shared arm/libcle.o -o arm/libcle.so
	
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

clextract-arm: clextract.c
	arm-linux-gnueabi-gcc -c clextract.c -o arm/clextract.o
	arm-linux-gnueabi-gcc -L$(LIB)/arm -Wall arm/clextract.o -o arm/clextract -lcle

clextract-i386: clextract.c
	x86_64-linux-gnu-gcc -m32 -c clextract.c -o i386/clextract.o
	x86_64-linux-gnu-gcc -m32 -L$(LIB)/i386 -Wall i386/clextract.o -o i386/clextract -lcle


install:
	for arch in "x86_64" "mips" "ppc" "i386" "arm" ; do \
		mkdir -p $(BINDIR)/$$arch; \
		mkdir -p $(LIBDIR)/$$arch; \
		cp $$arch/libcle.so $(LIBDIR)/$$arch; \
		cp $$arch/clextract $(BINDIR)/$$arch; \
	done

clean:
	 rm -f x86_64/*.so *.o clextract 
	 rm -f i386/*.so *.o clextract 
	 rm -f arm/*.so arm/*.o arm/clextract 
	 rm -f mips/*.so mips/*.o mips/clextract 
	 rm -f ppc/*.so arm/*.o arm/clextract 
