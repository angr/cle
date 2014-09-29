LIBDIR=$(VIRTUAL_ENV)/local/lib

cflags=-Wall -fstack-protector
cflags_ppc64=-I/cross/ppc/usr/include/powerpc-linux-gnu/

cc_x64=x86_64-linux-gnu-gcc $(cflags)
cc_mips=mips-linux-gnu-gcc $(cflags)
cc_mipsel=mipsel-linux-gnu-gcc $(cflags)
cc_ppc=powerpc-linux-gnu-gcc $(cflags)
cc_ppc64=powerpc-linux-gnu-gcc -m64 $(cflags)
cc_armel=arm-linux-gnueabi-gcc $(cflags)
cc_armhf=arm-linux-gnueabihf-gcc $(cflags)
cc_x86= gcc -m32 $(cflags)

all: ld_amd64 ld_armel ld_armhf ld_ppc ld_ppc64 ld_mips ld_mipsel ld_i386

ld_armel: ld_audit.c
	mkdir -p armel
	$(cc_armel) -o armel/cle_ld_audit.so ld_audit.c -fpic --shared

ld_armhf: ld_audit.c
ifeq (,$(shell which $(cc_armhf)))
	echo "CLE: no powerpc64 compiler"
else
	mkdir -p armhf
	$(cc_armhf) -o armhf/cle_ld_audit.so ld_audit.c -fpic --shared
endif

ld_ppc: ld_audit.c
	mkdir -p ppc
	$(cc_ppc) -o ppc/cle_ld_audit.so ld_audit.c -fpic --shared

ld_ppc64: ld_audit.c
ifeq (,$(shell which $(cc_ppc64)))
	echo "CLE: no powerpc64 compiler"
else
ifneq (, $(shell $(cc_ppc64) --version | egrep -o '4\.[5-9]'))
	mkdir -p ppc64
	$(cc_ppc64) $(cflags_ppc64) -o ppc64/cle_ld_audit.so ld_audit.c -fpic --shared
else
	echo "CLE: Your gcc version does not support ppc64, ignoring target"
endif
endif

ld_amd64: ld_audit.c
	mkdir -p x86_64
	$(cc_x64) -o x86_64/cle_ld_audit.so ld_audit.c -fpic --shared

ld_i386: ld_audit.c
	mkdir -p i386
	$(cc_x86) -o i386/cle_ld_audit.so ld_audit.c -fpic --shared

ld_mips: ld_audit.c
ifeq (,$(shell which $(cc_mips)))
	@echo "CLE: MIPS Compiler not present, ignoring target"
else
	mkdir -p mips
	$(cc_mips) -o mips/cle_ld_audit.so ld_audit.c -fpic --shared
endif

ld_mipsel: ld_audit.c
ifeq (,$(shell which $(cc_mipsel)))
	@echo "CLE: MIPS LSB Compiler not present, ignoring target"
else
	mkdir -p mipsel
	$(cc_mipsel) -o mipsel/cle_ld_audit.so ld_audit.c -fpic --shared
endif

clean:
	rm -f */*.so

install:
	mkdir -p $(DESTDIR)
	cp -a x86_64 ppc ppc64 mips mipsel armel armhf i386 $(DESTDIR)

install:
	for arch in "x86_64" "mips" "mipsel" "ppc" "ppc64" "i386" "armel" "armhf" ; do \
		mkdir -p $(LIBDIR)/$$arch; \
		cp $$arch/cle_ld_audit.so $(LIBDIR)/$$arch; \
	done


