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

x86_64: x86_64/libcle.so x86_64/libcle_static.so x86_64/ccle

x86_64/libcle.so: x86_64/libcle.o
	$(cc_x64) -shared $^ -o $@

x86_64/libcle.o: libcle.c
	mkdir -p x86_64
	$(cc_x64) -c -fpic $^ -o $@

x86_64/libcle_static.so: x86_64/libcle_static.o
	$(cc_x64) -shared $^ -o $@

x86_64/libcle_static.o: libcle_static.c
	mkdir -p x86_64
	$(cc_x64) -c -fpic $^ -o $@

x86_64/ccle: x86_64/ccle.o
	$(cc_x64) -L$(LIB)/x86_64 -Wall $^ -o $@ -lcle -lcle_static

x86_64/ccle.o: ccle.c
	$(cc_x64) -c $^ -o $@

i386: i386/libcle.so i386/libcle_static.so i386/ccle

i386/libcle.so: i386/libcle.o
	$(cc_x64) -shared $^ -o $@

i386/libcle.o: libcle.c
	mkdir -p i386
	$(cc_x64) -c -fpic $^ -o $@

i386/libcle_static.so: i386/libcle_static.o
	$(cc_x64) -shared $^ -o $@

i386/libcle_static.o: libcle_static.c
	mkdir -p i386
	$(cc_x64) -c -fpic $^ -o $@

i386/ccle: i386/ccle.o
	$(cc_x64) -L$(LIB)/i386 -Wall $^ -o $@ -lcle -lcle_static

i386/ccle.o: ccle.c
	$(cc_x64) -c $^ -o $@

mips: mips/libcle.so mips/libcle_static.so mips/ccle

mips/libcle.so: mips/libcle.o
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	$(cc_mips) -shared $^ -o $@
endif

mips/libcle.o: libcle.c
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	mkdir -p mips
	$(cc_mips) -c -fpic $^ -o $@
endif

mips/libcle_static.so: mips/libcle_static.o
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	$(cc_mips) -shared $^ -o $@
endif

mips/libcle_static.o: libcle_static.c
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	mkdir -p mips
	$(cc_mips) -c -fpic $^ -o $@
endif

mips/ccle: mips/ccle.o
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	$(cc_mips) -L$(LIB)/mips -Wall $^ -o $@ -lcle -lcle_static
endif

mips/ccle.o: ccle.c
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	mkdir -p mips
	$(cc_mips) -c $^ -o $@
endif

mipsel: mipsel/libcle.so mipsel/libcle_static.so mipsel/ccle

mipsel/libcle.so: mipsel/libcle.o
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_mipsel) -shared $^ -o $@
endif

mipsel/libcle.o: libcle.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p mipsel
	$(cc_mipsel) -c -fpic $^ -o $@
endif

mipsel/libcle_static.so: mipsel/libcle_static.o
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_mipsel) -shared $^ -o $@
endif

mipsel/libcle_static.o: libcle_static.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p mipsel
	$(cc_mipsel) -c -fpic $^ -o $@
endif

mipsel/ccle: mipsel/ccle.o
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_mipsel) -c ccle.c -o mipsel/ccle.o
	$(cc_mipsel) -L$(LIB)/mipsel -Wall $^ -o $@ -lcle -lcle_static
endif

mipsel/ccle.o: ccle.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_mipsel) -c $^ -o $@
endif

ppc: ppc/libcle.so ppc/libcle_static.so ppc/ccle

ppc/libcle.so: ppc/libcle.o
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	$(cc_ppc) -shared $^ -o $@
endif

ppc/libcle.o: libcle.c
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	mkdir -p ppc
	$(cc_ppc) -c -fpic $^ -o $@
endif

ppc/libcle_static.so: ppc/libcle_static.o
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	$(cc_ppc) -shared $^ -o $@
endif

ppc/libcle_static.o: libcle_static.c
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	mkdir -p ppc
	$(cc_ppc) -c -fpic $^ -o $@
endif

ppc/ccle: ppc/ccle.o
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	$(cc_ppc) -L$(LIB)/ppc -Wall $^ -o $@ -lcle -lcle_static
endif

ppc/ccle.o: ccle.c
ifeq (,$(shell which $(cc_ppc)))
	echo "CLE: no powerpc compiler"
else
	mkdir -p ppc
	$(cc_ppc) -c $^ -o $@
endif

ppc64: ppc64/libcle.so ppc64/libcle_static.so ppc64/ccle

ppc64/libcle.so: ppc64/libcle.o
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	$(cc_ppc64) $(cflags_ppc64) -shared $^ -o $@
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

ppc64/libcle.o: libcle.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	mkdir -p ppc64
	$(cc_ppc64) $(cflags_ppc64) -c -fpic $^ -o $@
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

ppc64/libcle_static.so: ppc64/libcle_static.o
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	$(cc_ppc64) $(cflags_ppc64) -shared $^ -o $@
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

ppc64/libcle_static.o: libcle_static.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	mkdir -p ppc64
	$(cc_ppc64) $(cflags_ppc64) -c -fpic $^ -o $@
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

ppc64/ccle: ppc64/ccle.o
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	$(cc_ppc64) $(cflags_ppc64) -L$(LIB)/ppc64 -Wall $^ -o $@ -lcle -lcle_static
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

ppc64/ccle.o: ccle.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]\.[0-9]'))
	mkdir -p ppc64
	$(cc_ppc64) $(cflags_ppc64) -c $^ -o $@
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

armel: armel/libcle.so armel/libcle_static.so armel/ccle

armel/libcle.so: armel/libcle.o
	$(cc_armel) -shared $^ -o $@

armel/libcle.o: libcle.c
	mkdir -p armel
	$(cc_armel) -c -fpic $^ -o $@

armel/libcle_static.so: armel/libcle_static.o
	$(cc_armel) -shared $^ -o $@

armel/libcle_static.o: libcle_static.c
	mkdir -p armel
	$(cc_armel) -c -fpic $^ -o $@

armel/ccle: armel/ccle.o
	mkdir -p armel
	$(cc_armel) -L$(LIB)/armel -Wall $^ -o $@ -lcle -lcle_static

armel/ccle.o: ccle.c
	$(cc_armel) -c $^ -o $@

armhf: armhf/libcle.so armhf/libcle_static.so armhf/ccle

armhf/libcle.so: armhf/libcle.o
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_armhf) -shared $^ -o $@
endif

armhf/libcle.o: libcle.c
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p armhf
	$(cc_armhf) -c -fpic $^ -o $@
endif

armhf/libcle_static.so: armhf/libcle_static.o
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_armhf) -shared $^ -o $@
endif

armhf/libcle_static.o: libcle_static.c
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p armhf
	$(cc_armhf) -c -fpic $^ -o $@
endif

armhf/ccle: armhf/ccle.o
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	$(cc_armhf) -L$(LIB)/armhf -Wall $^ -o $@ -lcle -lcle_static
endif

armhf/ccle.o: ccle.c
ifeq (,$(shell which $(cc_armhf)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p ccle
	$(cc_armhf) -c $^ -o $@
endif

.PHONY: install clean
install:
	for arch in "x86_64" "mips" "mipsel" "ppc" "ppc64" "i386" "armel" "armhf" ; do \
		mkdir -p $(BINDIR)/$$arch; \
		mkdir -p $(LIBDIR)/$$arch; \
		cp $$arch/libcle.so $(LIBDIR)/$$arch; \
		cp $$arch/libcle_static.so $(LIBDIR)/$$arch; \
		cp $$arch/ccle $(BINDIR)/$$arch; \
	done

clean:
	 rm -f x86_64/*.so x86_64/*.o x86_64/ccle 
	 rm -f i386/*.so i386/*.o i386/ccle 
	 rm -f armel/*.so armel/*.o armel/ccle 
	 rm -f armhf/*.so armhf/*.o armhf/ccle 
	 rm -f mips/*.so mips/*.o mips/ccle 
	 rm -f mipsel/*.so mipsel/*.o mipsel/ccle 
	 rm -f ppc/*.so ppc/*.o ppc/ccle 
	 rm -f ppc64/*.so ppc64/*.o ppc64/ccle 
