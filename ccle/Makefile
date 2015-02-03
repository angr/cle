LIB:=$(CURDIR)
BINDIR=$(VIRTUAL_ENV)/local/bin
LIBDIR=$(VIRTUAL_ENV)/local/lib

cflags=-Wall -fstack-protector -fdiagnostics-color=auto
cflags_ppc64=-I/cross/ppc/usr/include/powerpc-linux-gnu/
mips_cflags=-Wall
ppc_cflags=-Wall
arm_cflags=-Wall

cc_x64=x86_64-linux-gnu-gcc $(cflags)
cc_mips=mips-linux-gnu-gcc $(mips_cflags) 
cc_mipsel=mipsel-linux-gnu-gcc $(mips_cflags) 
cc_ppc=powerpc-linux-gnu-gcc $(ppc_cflags)
cc_ppc64=powerpc-linux-gnu-gcc -m64 $(ppc_cflags)
cc_armel=arm-linux-gnueabi-gcc $(arm_cflags)
cc_armhf=arm-linux-gnueabihf-gcc $(arm_cflags)
cc_x86= gcc -m32 $(cflags)

all: x86_64 mips mipsel ppc armel armhf i386 ppc64

x86_64: libcle-x86_64 libcle_static-x86_64 cle-x86_64
mips: libcle-mips libcle_static-mips cle-mips
mipsel: libcle-mipsel libcle_static-mipsel cle-mipsel
ppc: libcle-ppc libcle_static-ppc cle-ppc
ppc64: libcle-ppc64 libcle_static-ppc64 cle-ppc64
armel: libcle-armel libcle_static-armel cle-armel
armhf: libcle-armhf libcle_static-armhf cle-armhf
i386: libcle-i386 libcle_static-i386 cle-i386

libcle-x86_64: libcle.c
	mkdir -p x86_64
	$(cc_x64) -c -fpic libcle.c -o x86_64/libcle.o
	$(cc_x64) -shared x86_64/libcle.o -o x86_64/libcle.so

libcle_static-x86_64: libcle_static.c
	mkdir -p x86_64
	$(cc_x64) -c -fpic libcle_static.c -o x86_64/libcle_static.o
	$(cc_x64) -shared x86_64/libcle_static.o -o x86_64/libcle_static.so

cle-x86_64: cle.c
	$(cc_x64) -c cle.c -o x86_64/cle.o
	$(cc_x64) -L$(LIB)/x86_64 -Wall x86_64/cle.o -o x86_64/cle -lcle -lcle_static

libcle-i386: libcle.c
	mkdir -p i386
	$(cc_x86) -c -fpic libcle.c -o i386/libcle.o
	$(cc_x86) -shared i386/libcle.o -o i386/libcle.so

libcle_static-i386: libcle_static.c
	mkdir -p i386
	$(cc_x86) -c -fpic libcle_static.c -o i386/libcle_static.o
	$(cc_x86) -shared i386/libcle_static.o -o i386/libcle_static.so

cle-i386: cle.c
	$(cc_x86) -c cle.c -o i386/cle.o
	$(cc_x86) -L$(LIB)/i386 -Wall i386/cle.o -o i386/cle -lcle -lcle_static

libcle-mips: libcle.c
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	mkdir -p mips
	$(cc_mips) -c -fpic libcle.c -o mips/libcle.o
	$(cc_mips) -shared mips/libcle.o -o mips/libcle.so
endif

libcle_static-mips: libcle_static.c
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	mkdir -p mips
	$(cc_mips) -c -fpic libcle_static.c -o mips/libcle_static.o
	$(cc_mips) -shared mips/libcle_static.o -o mips/libcle_static.so
endif

cle-mips: cle.c
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	$(cc_mips) -c cle.c -o mips/cle.o
	$(cc_mips) -L$(LIB)/mips -Wall mips/cle.o -o mips/cle -lcle -lcle_static
endif

libcle-mipsel: libcle.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p mipsel
	$(cc_mipsel) -c -fpic libcle.c -o mipsel/libcle.o
	$(cc_mipsel) -shared mipsel/libcle.o -o mipsel/libcle.so
endif

libcle_static-mipsel: libcle_static.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p mipsel
	$(cc_mipsel) -c -fpic libcle_static.c -o mipsel/libcle_static.o
	$(cc_mipsel) -shared mipsel/libcle_static.o -o mipsel/libcle_static.so
endif

cle-mipsel: cle.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_mipsel) -c cle.c -o mipsel/cle.o
	$(cc_mipsel) -L$(LIB)/mipsel -Wall mipsel/cle.o -o mipsel/cle -lcle -lcle_static
endif

libcle-ppc: libcle.c
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	mkdir -p ppc
	$(cc_ppc) -c -fpic libcle.c -o ppc/libcle.o
	$(cc_ppc) -shared ppc/libcle.o -o ppc/libcle.so
endif

libcle_static-ppc: libcle_static.c
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	mkdir -p ppc
	$(cc_ppc) -c -fpic libcle_static.c -o ppc/libcle_static.o
	$(cc_ppc) -shared ppc/libcle_static.o -o ppc/libcle_static.so
endif

cle-ppc: cle.c
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	$(cc_ppc) -c cle.c -o ppc/cle.o
	$(cc_ppc) -L$(LIB)/ppc -Wall ppc/cle.o -o ppc/cle -lcle -lcle_static
endif

libcle-ppc64: libcle.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	mkdir -p ppc64
	$(cc_ppc64) $(cflags_ppc64) -c -fpic libcle.c -o ppc64/libcle.o
	$(cc_ppc64) $(cflags_ppc64) -shared ppc64/libcle.o -o ppc64/libcle.so
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

libcle_static-ppc64: libcle_static.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	mkdir -p ppc64
	$(cc_ppc64) $(cflags_ppc64) -c -fpic libcle_static.c -o ppc64/libcle_static.o
	$(cc_ppc64) $(cflags_ppc64) -shared ppc64/libcle_static.o -o ppc64/libcle_static.so
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

cle-ppc64: cle.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	$(cc_ppc64) $(cflags_ppc64) -c cle.c -o ppc64/cle.o
	$(cc_ppc64) $(cflags_ppc64) -L$(LIB)/ppc64 -Wall ppc64/cle.o -o ppc64/cle -lcle -lcle_static
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

libcle-armel: libcle.c
	mkdir -p armel
	$(cc_armel) -c -fpic libcle.c -o armel/libcle.o
	$(cc_armel) -shared armel/libcle.o -o armel/libcle.so

libcle_static-armel: libcle_static.c
	mkdir -p armel
	$(cc_armel) -c -fpic libcle_static.c -o armel/libcle_static.o
	$(cc_armel) -shared armel/libcle_static.o -o armel/libcle_static.so

cle-armel: cle.c
	$(cc_armel) -c cle.c -o armel/cle.o
	$(cc_armel) -L$(LIB)/armel -Wall armel/cle.o -o armel/cle -lcle -lcle_static

libcle-armhf: libcle.c
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p armhf
	$(cc_armhf) -c -fpic libcle.c -o armhf/libcle.o
	$(cc_armhf) -shared armhf/libcle.o -o armhf/libcle.so
endif

libcle_static-armhf: libcle_static.c
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p armhf
	$(cc_armhf) -c -fpic libcle_static.c -o armhf/libcle_static.o
	$(cc_armhf) -shared armhf/libcle_static.o -o armhf/libcle_static.so
endif

cle-armhf: cle.c
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_armhf) -c cle.c -o armhf/cle.o
	$(cc_armhf) -L$(LIB)/armhf -Wall armhf/cle.o -o armhf/cle -lcle
endif

install:
	for arch in "x86_64" "mips" "mipsel" "ppc" "ppc64" "i386" "armel" "armhf" ; do \
		mkdir -p $(BINDIR)/$$arch; \
		mkdir -p $(LIBDIR)/$$arch; \
		cp $$arch/libcle.so $(LIBDIR)/$$arch; \
		cp $$arch/cle $(BINDIR)/$$arch; \
	done

clean:
	 rm -f x86_64/*.so x86_64/*.o x86_64/cle 
	 rm -f i386/*.so i386/*.o i386/cle 
	 rm -f armel/*.so armel/*.o armel/cle 
	 rm -f armhf/*.so armhf/*.o armhf/cle 
	 rm -f mips/*.so mips/*.o mips/cle 
	 rm -f mipsel/*.so mipsel/*.o mipsel/cle 
	 rm -f ppc/*.so ppc/*.o ppc/cle 
	 rm -f ppc64/*.so ppc64/*.o ppc64/cle 
