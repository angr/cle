#include <elf.h>
//#include "cle.h"

char* alloc_load_sht_strtab(ElfW(Ehdr) ehdr, ElfW(Shdr) *shdr, FILE *f);
const char *sh_type_tostr(ElfW(Word) sh_type);
ElfW(Shdr) *get_shdr(ElfW(Ehdr) ehdr, FILE *f);
void print_shdr(ElfW(Shdr) *shdr, int shdr_size, char* sht_strtab);
void *get_ptr(ElfW(Addr) vaddr, struct segment *text, struct segment *data);
void print_static_strtabs(ElfW(Shdr) *shdr, int sh_size, struct segment *text, struct segment *data);
void _print_symtab(ElfW(Sym) *symtab, int lastindex, char* strtab);
void print_static_symtab(ElfW(Shdr) *shdr, int sh_size, ElfW(Sym) *symtab, struct segment *text, struct segment *data);
ElfW(Sym)* alloc_load_sht_symtab(ElfW(Shdr) *shdr, size_t sh_size, FILE *f);
