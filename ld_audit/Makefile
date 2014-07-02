LIBDIR=$(VIRTUAL_ENV)/local/lib

all: ld_audit-amd64 ld_audit-ppc32 ld_audit-mips32 ld_audit-arm ld_audit-i386

ld_audit-arm: ld_audit.c
	mkdir -p arm
	arm-linux-gnueabi-gcc -o arm/cle_ld_audit.so ld_audit.c -fpic --shared

ld_audit-ppc32: ld_audit.c
	mkdir -p ppc
	powerpc-linux-gnu-gcc -o ppc/cle_ld_audit.so ld_audit.c -fpic --shared

ld_audit-amd64: ld_audit.c
	mkdir -p x86_64
	gcc -o x86_64/cle_ld_audit.so ld_audit.c -fpic --shared

ld_audit-i386: ld_audit.c
	mkdir -p i386
	gcc -m32 -o i386/cle_ld_audit.so ld_audit.c -fpic --shared

ld_audit-mips32: ld_audit.c
	mkdir -p mips
	mips-linux-gnu-gcc -o mips/cle_ld_audit.so ld_audit.c -fpic --shared

clean:
	rm -f */*.so

install:
	mkdir -p $(DESTDIR)
	cp -a x86_64 ppc mips arm i386 $(DESTDIR)

install:
	for arch in "x86_64" "mips" "ppc" "i386" "arm" ; do \
		mkdir -p $(LIBDIR)/$$arch; \
		cp $$arch/cle_ld_audit.so $(LIBDIR)/$$arch; \
	done


