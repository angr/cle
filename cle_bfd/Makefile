all: cle_bfd

cle_bfd: cle_bfd.c
	gcc -Wall -c -fpic cle_bfd.c -o cle_bfd.o
	gcc -shared cle_bfd.o -o cle_bfd.so -lbfd-2.22-multiarch


