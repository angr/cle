all:
	make -C bfd
	make -C ccle
	make -C ld_audit

clean:
	make -C bfd clean
	make -C ccle clean
	make -C ld_audit clean

install:
	make -C bfd install
	make -C ccle install
	make -C ld_audit install
