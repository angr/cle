LIB:=$(CURDIR)
BINDIR=$(VIRTUAL_ENV)/local/bin
LIBDIR=$(VIRTUAL_ENV)/local/lib

cflags=-Wall -fstack-protector #-fdiagnostics-color=auto
cflags_ppc64=-I/cross/ppc/usr/include/powerpc-linux-gnu/

cc_x64=x86_64-linux-gnu-gcc $(cflags)
cc_mips=mips-linux-gnu-gcc $(cflags) 
cc_mipsel=mipsel-linux-gnu-gcc $(cflags) 
cc_ppc=powerpc-linux-gnu-gcc $(cflags)
cc_ppc64=powerpc-linux-gnu-gcc -m64 $(cflags)
cc_armel=arm-linux-gnueabi-gcc $(cflags)
cc_armhf=arm-linux-gnueabihf-gcc $(cflags)
cc_x86= gcc -m32 $(cflags)

all: x86_64 mips mipsel ppc armel armhf i386 ppc64

x86_64: libcle-x86_64 clextract-x86_64
mips: libcle-mips clextract-mips
mipsel: libcle-mipsel clextract-mipsel
ppc: libcle-ppc clextract-ppc
ppc64: libcle-ppc64 clextract-ppc64
armel: libcle-armel clextract-armel
armhf: libcle-armhf clextract-armhf
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
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	mkdir -p mips
	$(cc_mips) -c -fpic libcle.c -o mips/libcle.o
	$(cc_mips) -shared mips/libcle.o -o mips/libcle.so
endif

libcle-mipsel: libcle.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p mipsel
	$(cc_mipsel) -c -fpic libcle.c -o mipsel/libcle.o
	$(cc_mipsel) -shared mipsel/libcle.o -o mipsel/libcle.so
endif

clextract-mips: clextract.c
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	$(cc_mips) -c clextract.c -o mips/clextract.o
	$(cc_mips) -L$(LIB)/mips -Wall mips/clextract.o -o mips/clextract -lcle
endif

clextract-mipsel: clextract.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_mipsel) -c clextract.c -o mipsel/clextract.o
	$(cc_mipsel) -L$(LIB)/mipsel -Wall mipsel/clextract.o -o mipsel/clextract -lcle
endif

libcle-ppc: libcle.c
	mkdir -p ppc
	$(cc_ppc) -c -fpic libcle.c -o ppc/libcle.o
	$(cc_ppc) -shared ppc/libcle.o -o ppc/libcle.so

clextract-ppc: clextract.c
	$(cc_ppc) -c clextract.c -o ppc/clextract.o
	$(cc_ppc) -L$(LIB)/ppc -Wall ppc/clextract.o -o ppc/clextract -lcle

libcle-ppc64: libcle.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]'))
	mkdir -p ppc64
	$(cc_ppc64) $(cflags_ppc64) -c -fpic libcle.c -o ppc64/libcle.o
	$(cc_ppc64) $(cflags_ppc64) -shared ppc64/libcle.o -o ppc64/libcle.so
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

clextract-ppc64: clextract.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]'))
	$(cc_ppc64) $(cflags_ppc64) -c clextract.c -o ppc64/clextract.o
	$(cc_ppc64) $(cflags_ppc64) -L$(LIB)/ppc64 -Wall ppc64/clextract.o -o ppc64/clextract -lcle
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

libcle-armel: libcle.c
	mkdir -p armel
	$(cc_armel) -c -fpic libcle.c -o armel/libcle.o
	$(cc_armel) -shared armel/libcle.o -o armel/libcle.so

clextract-armel: clextract.c
	$(cc_armel) -c clextract.c -o armel/clextract.o
	$(cc_armel) -L$(LIB)/armel -Wall armel/clextract.o -o armel/clextract -lcle

libcle-armhf: libcle.c
	mkdir -p armhf
	$(cc_armhf) -c -fpic libcle.c -o armhf/libcle.o
	$(cc_armhf) -shared armhf/libcle.o -o armhf/libcle.so

clextract-armhf: clextract.c
	$(cc_armhf) -c clextract.c -o armhf/clextract.o
	$(cc_armhf) -L$(LIB)/armhf -Wall armhf/clextract.o -o armhf/clextract -lcle

install:
	for arch in "x86_64" "mips" "mipsel" "ppc" "ppc64" "i386" "armel" "armhf" ; do \
		mkdir -p $(BINDIR)/$$arch; \
		mkdir -p $(LIBDIR)/$$arch; \
		cp $$arch/libcle.so $(LIBDIR)/$$arch; \
		cp $$arch/clextract $(BINDIR)/$$arch; \
	done

clean:
	 rm -f x86_64/*.so x86_64/*.o x86_64/clextract 
	 rm -f i386/*.so i386/*.o i386/clextract 
	 rm -f armel/*.so armel/*.o armel/clextract 
	 rm -f armhf/*.so armhf/*.o armhf/clextract 
	 rm -f mips/*.so mips/*.o mips/clextract 
	 rm -f mipsel/*.so mipsel/*.o mipsel/clextract 
	 rm -f ppc/*.so ppc/*.o ppc/clextract 
	 rm -f ppc64/*.so ppc64/*.o ppc64/clextract 
