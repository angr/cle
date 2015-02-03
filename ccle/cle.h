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


/* Get a string from the string table at a given index*/
char *get_str(char* strtab, int idx)
{
	if (strtab == NULL)
		return NULL;
    char *str = &strtab[idx];
    return str;
}


