LIB:=$(CURDIR)
BINDIR=$(VIRTUAL_ENV)/local/bin
LIBDIR=$(VIRTUAL_ENV)/local/lib

cflags=-Wall -fstack-protector #-fdiagnostics-color=auto

cc_x64=x86_64-linux-gnu-gcc $(cflags)
cc_mips=mips-linux-gnu-gcc $(cflags) 
cc_ppc=powerpc-linux-gnu-gcc $(cflags)
cc_arm=arm-linux-gnueabi-gcc $(cflags)
cc_x86= gcc -m32 $(cflags)

all: x86_64 mips ppc arm i386

x86_64: libcle-x86_64 clextract-x86_64
mips: libcle-mips clextract-mips
ppc: libcle-ppc clextract-ppc
arm: libcle-arm clextract-arm
i386: libcle-i386 clextract-i386


libcle-x86_64: libcle.c
	mkdir -p x86_64
	$(cc_x64) -c -fpic libcle.c -o x86_64/libcle.o
	$(cc_x64) -shared x86_64/libcle.o -o x86_64/libcle.so
	
clextract-x86_64: clextract.c
	$(cc_x64) -c clextract.c -o x86_64/clextract.o
	$(cc_x64) -L$(LIB)/x86_64 -Wall x86_64/clextract.o -o x86_64/clextract -lcle

libcle-i386: libcle.c
	mkdir -p i386
	$(cc_x86) -c -fpic libcle.c -o i386/libcle.o
	$(cc_x86) -shared i386/libcle.o -o i386/libcle.so

clextract-i386: clextract.c
	$(cc_x86) -c clextract.c -o i386/clextract.o
	$(cc_x86) -L$(LIB)/i386 -Wall i386/clextract.o -o i386/clextract -lcle

libcle-mips: libcle.c
	mkdir -p mips
	$(cc_mips) -c -fpic libcle.c -o mips/libcle.o
	$(cc_mips) -shared mips/libcle.o -o mips/libcle.so

clextract-mips: clextract.c
	$(cc_mips) -c clextract.c -o mips/clextract.o
	$(cc_mips) -L$(LIB)/mips -Wall mips/clextract.o -o mips/clextract -lcle

libcle-ppc: libcle.c
	mkdir -p ppc
	$(cc_ppc) -c -fpic libcle.c -o ppc/libcle.o
	$(cc_ppc) -shared ppc/libcle.o -o ppc/libcle.so

clextract-ppc: clextract.c
	$(cc_ppc) -c clextract.c -o ppc/clextract.o
	$(cc_ppc) -L$(LIB)/ppc -Wall ppc/clextract.o -o ppc/clextract -lcle

libcle-arm: libcle.c
	mkdir -p arm
	$(cc_arm) -c -fpic libcle.c -o arm/libcle.o
	$(cc_arm) -shared arm/libcle.o -o arm/libcle.so

clextract-arm: clextract.c
	$(cc_arm) -c clextract.c -o arm/clextract.o
	$(cc_arm) -L$(LIB)/arm -Wall arm/clextract.o -o arm/clextract -lcle

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
