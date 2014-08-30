LIBDIR=$(VIRTUAL_ENV)/local/lib

cflags=-Wall -fstack-protector

cc_x64=x86_64-linux-gnu-gcc $(cflags)
cc_mips=mips-linux-gnu-gcc $(cflags)
cc_ppc=powerpc-linux-gnu-gcc $(cflags)
cc_ppc64=powerpc-linux-gnu-gcc -m64 $(cflags)
cc_arm=arm-linux-gnueabi-gcc $(cflags)
cc_x86= gcc -m32 $(cflags)

all: ld_amd64 ld_arm ld_ppc ld_ppc64 ld_mips ld_arm ld_i386

ld_arm: ld_audit.c
	mkdir -p arm
	$(cc_arm) -o arm/cle_ld_audit.so ld_audit.c -fpic --shared

ld_ppc: ld_audit.c
	mkdir -p ppc
	$(cc_ppc) -o ppc/cle_ld_audit.so ld_audit.c -fpic --shared

ld_ppc64: ld_audit.c
	mkdir -p ppc64
	$(cc_ppc64) -o ppc64/cle_ld_audit.so ld_audit.c -fpic --shared

ld_amd64: ld_audit.c
	mkdir -p x86_64
	$(cc_x64) -o x86_64/cle_ld_audit.so ld_audit.c -fpic --shared

ld_i386: ld_audit.c
	mkdir -p i386
	$(cc_x86) -o i386/cle_ld_audit.so ld_audit.c -fpic --shared

ld_mips: ld_audit.c
	mkdir -p mips
	$(cc_mips) -o mips/cle_ld_audit.so ld_audit.c -fpic --shared

clean:
	rm -f */*.so

install:
	mkdir -p $(DESTDIR)
	cp -a x86_64 ppc ppc64 mips arm i386 $(DESTDIR)

install:
	for arch in "x86_64" "mips" "ppc" "ppc64" "i386" "arm" ; do \
		mkdir -p $(LIBDIR)/$$arch; \
		cp $$arch/cle_ld_audit.so $(LIBDIR)/$$arch; \
	done


