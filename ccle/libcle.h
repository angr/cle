#include <elf.h>
#include <link.h>
/* ELFxx_ST_BIND is either ELF32_STBIND or ELF64_STBIND. Though these guys boil
 * down to the same thing (see elf.h), let's play the game and call the correct
 * one.  */
#define ST_BIND(x) _XST_BIND(ELF, __ELF_NATIVE_CLASS, _ST_BIND,  x)
#define _XST_BIND(elf, class, name, x)  __XST_BIND(elf, class, name, x )
#define __XST_BIND(elf, class, name, x) elf##class##name(x)

/* Same thing with ELFxx_ST_TYPE */
#define ST_TYPE(x) _XST_TYPE(ELF, __ELF_NATIVE_CLASS, _ST_TYPE,  x)
#define _XST_TYPE(elf, class, name, x)  __XST_TYPE(elf, class, name, x )
#define __XST_TYPE(elf, class, name, x) elf##class##name(x)



/* Same thing with ELFxx_R_SYM*/
#define ELF_R_SYM(x) _ELF_R_SYM(ELF, __ELF_NATIVE_CLASS, _R_SYM,  x)
#define _ELF_R_SYM(elf, class, name, x)  __ELF_R_SYM(elf, class, name, x )
#define __ELF_R_SYM(elf, class, name, x) elf##class##name(x)

#define ELF_R_TYPE(x) _ELF_R_TYPE(ELF, __ELF_NATIVE_CLASS, _R_TYPE,  x)
#define _ELF_R_TYPE(elf, class, name, x)  __ELF_R_TYPE(elf, class, name, x )
#define __ELF_R_TYPE(elf, class, name, x) elf##class##name(x)



/* Representation of a segment.
 * @vaddr is the ELF virtual address and is of type Elfxx_Addr
 * @img is our local load address, e.g., what address malloc gives us, and is
 * of type char*
 * */
struct segment
{
    ElfW(Addr) vaddr; // Virtual address
    ElfW(Xword) memsz; // Size in memory
    ElfW(Xword) filesz; // Size in elf file
    ElfW(Off) offset; // Size in elf file
    char *img; // Pointer to in-memory image
};

/*
 * _functions are called by higher level functions of 
 * the same names in libcle_cypes.h
 * __functions are unsafe functions
 */

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
const char *sh_type_tostr(ElfW(Word) sh_type);
char *sh_index_tostr(ElfW(Half) ndx);
char *symb_info_tostr(unsigned char info);
const char * pt_type_tostr(ElfW(Word) p_type);
int alloc_segment(int pt_index, ElfW(Phdr) *phdr, struct segment *s_in);
void free_segment(struct segment **segment);
int load_segment(struct segment *segment, FILE *f);
char *_get_type(ElfW(Ehdr) ehdr);
char *ei_data_tostr(unsigned char val);
