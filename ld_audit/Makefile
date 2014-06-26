DESTDIR=$(VIRTUAL_ENV)/opt

all: ld_audit-amd64 ld_audit-ppc32 ld_audit-mips32 ld_audit-arm

ld_audit-arm: ld_audit.c
	mkdir -p arm
	arm-linux-gnueabi-gcc -o arm/cle_ld_audit.so ld_audit.c -fpic --shared

ld_audit-ppc32: ld_audit.c
	mkdir -p ppc
	powerpc-linux-gnu-gcc -o ppc/cle_ld_audit.so ld_audit.c -fpic --shared

ld_audit-amd64: ld_audit.c
	mkdir -p x86_64
	gcc -o x86_64/ld_audit.so ld_audit.c -fpic --shared

ld_audit-mips32: ld_audit.c
	mkdir -p mips
	mips-linux-gnu-gcc -o mips/cle_ld_audit.so ld_audit.c -fpic --shared

clean:
	rm -f */ld_audit.so

install:
	mkdir -p $(DESTDIR)
	cp -a x86_64 ppc mips arm $(DESTDIR)
