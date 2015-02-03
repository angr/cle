#include <elf.h>
#include <link.h>
//#include "cle.h"
/* ELFxx_ST_BIND is either ELF32_STBIND or ELF64_STBIND. Though these guys boil
 * down to the same thing (see elf.h), let's play the game and call the correct
 * one.  */

unsigned short get_elf_class(FILE *f);
int find_text_index(ElfW(Ehdr) ehdr, ElfW(Phdr) *phdr);
int find_data_index(ElfW(Ehdr) ehdr, ElfW(Phdr) *phdr);
ElfW(Phdr) *get_phdr(ElfW(Ehdr), FILE *f);
ElfW(Dyn) *get_dynamic(ElfW(Phdr) *phdr, int count, FILE *f);
ElfW(Word) _get_strtab_sz(ElfW(Dyn) *dynamic);
ElfW(Addr) _get_strtab_vaddr(ElfW(Dyn) *dynamic);
ElfW(Word) get_symtab_syment(ElfW(Dyn) *dynamic);
ElfW(Addr) _get_symtab_vaddr(ElfW(Dyn) *dynamic);
ElfW(Word) get_dyn_val(ElfW(Dyn) *dynamic, ElfW(Word) d_tag);
ElfW(Addr) get_dyn_ptr_addr(ElfW(Dyn) *dynamic, ElfW(Sword) d_tag);
int addr_belongs_to_mem(ElfW(Addr) vaddr1, ElfW(Addr) vaddr2, ElfW(Word) size);
ElfW(Off) addr_offset_from_segment(ElfW(Addr) addr, struct segment *segment);
char *__get_str(char* strtab, int idx);
char *_get_arch(ElfW(Ehdr) ehdr);
const char* d_tag_tostr(ElfW(Sword) d_tag);
//const char *sh_type_tostr(ElfW(Word) sh_type);
const char *sh_index_tostr(ElfW(Half) ndx);
const char *symb_bind_tostr(int info);
const char *symb_type_tostr(int info);
const char * pt_type_tostr(ElfW(Word) p_type);
int alloc_segment(int pt_index, ElfW(Phdr) *phdr, struct segment *s_in);
void free_segment(struct segment **segment);
int load_segment(struct segment *segment, FILE *f);
char *_get_type(ElfW(Ehdr) ehdr);
char *ei_data_tostr(unsigned char val);
void print_rela_ent(ElfW(Rela) rela, ElfW(Sym) *symtab, char *strtab, const char *label);
void print_rel_ent(ElfW(Rel) rel, ElfW(Sym) *symtab, char *strtab, const char *label);
