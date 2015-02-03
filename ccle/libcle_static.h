#include <elf.h>
//#include "cle.h"

char* alloc_load_sht_strtab(ElfW(Ehdr) ehdr, ElfW(Shdr) *shdr, FILE *f);
const char *sh_type_tostr(ElfW(Word) sh_type);
ElfW(Shdr) *get_shdr(ElfW(Ehdr) ehdr, FILE *f);
void print_shdr(ElfW(Shdr) *shdr, int shdr_size, char* sht_strtab);
