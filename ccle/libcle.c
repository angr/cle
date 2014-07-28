#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <string.h>
#include "libcle.h"


/*################################################################################
# CLÉ's Main lib - Not CTYPES friendly - Not supposed to be called from python #
                    ### Use libcle_ctypes instead ###
################################################################################*/


unsigned short get_elf_class(FILE *f)
{
    size_t count;
    ElfW(Ehdr) ehdr;

    rewind(f);
    count = fread(&ehdr, sizeof(ElfW(Ehdr)), 1, f);

    if (count == 0)
        return count;

    return ehdr.e_ident[EI_CLASS];
}



/* Find the index of the text segment into the program header table*/
int find_text_index(ElfW(Ehdr) ehdr, ElfW(Phdr) *phdr)
{
    int i;
    for (i=0; i<ehdr.e_phnum; i++)
        if ((phdr[i].p_type == PT_LOAD) && (phdr[i].p_filesz ==
                    phdr[i].p_memsz))
                return i;

    return -EBADSLT; // Invalid slot
}

/* Find the index of the data segment into the program header table*/
int find_data_index(ElfW(Ehdr) ehdr, ElfW(Phdr) *phdr)
{
    int i;
    for (i=0; i<ehdr.e_phnum; i++)
        if ((phdr[i].p_filesz < phdr[i].p_memsz) && (phdr[i].p_type ==
                    PT_LOAD))
            return i;
    return -EBADSLT; // Invalid slot
}



/* Read the program header table from f and return a pointer to it */
ElfW(Phdr) *get_phdr(ElfW(Ehdr) ehdr, FILE *f)
{
    ElfW(Phdr) *phdr;
    int i;

    phdr = malloc(ehdr.e_phentsize * ehdr.e_phnum);
    if (!phdr)
        return NULL;

    for (i = 0; i < ehdr.e_phnum; i++){
        fseek(f, ehdr.e_phoff + (i * ehdr.e_phentsize), SEEK_SET);
        fread(&phdr[i], ehdr.e_phentsize, 1, f);
    }
    return phdr;
}


/* Load the dynamic segment into memory
 * It will be accessible by the global variable @dynamic
 * */

ElfW(Dyn) *get_dynamic(ElfW(Phdr) *phdr, int count, FILE *f)
{
    int i;
    ElfW(Dyn) *dynamic;
    for (i=0; i <count; i++)
        if ((phdr[i].p_type == PT_DYNAMIC) && (phdr[i].p_filesz > 0))
        {
            dynamic = malloc(phdr[i].p_filesz);
            if (!dynamic)
                return NULL;
            fseek(f, phdr[i].p_offset, SEEK_SET);
            fread(dynamic, phdr[i].p_filesz, 1, f);
            return dynamic;
        }
    return NULL;
}

/* Get the size of the string table */
ElfW(Word) _get_strtab_sz(ElfW(Dyn) *dynamic)
{
    return get_dyn_val(dynamic, DT_STRSZ);
}

/* Get the virtual address of the string  table*/
ElfW(Addr) _get_strtab_vaddr(ElfW(Dyn) *dynamic)
{
    return get_dyn_ptr_addr(dynamic, DT_STRTAB);
}

/* Get the size of one entry of the symbol table */
ElfW(Word) get_symtab_syment(ElfW(Dyn) *dynamic)
{
    return get_dyn_val(dynamic, DT_SYMENT);
}

/* Get the virtual address of the string table*/
ElfW(Addr) _get_symtab_vaddr(ElfW(Dyn) *dynamic)
{
    return get_dyn_ptr_addr(dynamic, DT_SYMTAB);
}


/* Does @vaddr1 belong to the memory zone defined by vaddr2 -> vaddr2 + size */
int addr_belongs_to_mem(ElfW(Addr) vaddr1, ElfW(Addr) vaddr2, ElfW(Word) size)
{
    return ((vaddr1 > vaddr2) && (vaddr1 < vaddr2 + size));
}

int addr_belongs_to_segment(ElfW(Addr) addr, struct segment *segment)
{
    return (addr_belongs_to_mem(addr, segment->vaddr, segment->memsz));
}

// Does address @addr belong to @segment ?
ElfW(Off) addr_offset_from_segment(ElfW(Addr) addr, struct segment *segment)
{
    if (!segment)
    {
        printf("NO SEGMENT\n");
        return 0;
    }

    if (addr_belongs_to_mem(addr, segment->vaddr, segment->memsz))
        return (addr - segment->vaddr);
    else
        return 0;
}

/* Get a string from the string table at a given index*/
char *__get_str(char* strtab, int idx)
{
    char *str = &strtab[idx];
    return str;
}

/* This function gets the value associated with the dynamic section
 * corresponding to d_tag*/
ElfW(Word) get_dyn_val(ElfW(Dyn) *dynamic, ElfW(Word) d_tag)
{
    int i = 0;
    ElfW(Word) val = -ENODATA;

    /* Find vaddr and size */
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
        if (dynamic[i].d_tag == d_tag)
            val = dynamic[i].d_un.d_val;
    return val;
}

/* Get the d_un->d_ptr value of the section denoted by
 * d_tag in the Dynamic table. 
 */
ElfW(Addr) get_dyn_ptr_addr(ElfW(Dyn) *dynamic, ElfW(Sword) d_tag)
{
    int i;

    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
        if (dynamic[i].d_tag == d_tag)
            return dynamic[i].d_un.d_ptr;
    return (ElfW(Addr)) -ENODATA; // unsigned
}


/* Loads a segment into memory, in the @segment structure, from file @f.
 * What we call segment here is anything represented in the program header
 * table*/
int load_segment(struct segment *segment, FILE *f)
{
    int size, i;

    if (!segment || !segment->img || !f)
        return -ENODATA;

    fseek(f, segment->offset, SEEK_SET);

    /* Read p_filesz bytes from file */
    size = fread(segment->img, segment->filesz, 1, f);
    if (size == 0)
        return -ENODATA;

    /* Extra bytes in memory are 0s (BSS)*/
    size = segment->memsz - segment->filesz;
    if (size > 0)
    {
        for (i=0; i<size; i++)
            segment->img[segment->filesz + i] = 0x0;
    }
    return 0;
}



/* Allocate memory for the segment represented by the entry at @pt_index in the
 * program header table @phdr.  * 
 * */
int alloc_segment(int pt_index, ElfW(Phdr) *phdr, struct segment *s_in)
{
    if (!s_in)
        return -ENODATA;

    if (pt_index < 0 || ! phdr)
        return -ENODATA;

    s_in->img = malloc(phdr[pt_index].p_memsz);
    if (!s_in->img)
        return -ENOMEM;

    s_in->offset = phdr[pt_index].p_offset;
    s_in->memsz = phdr[pt_index].p_memsz;
    s_in->filesz = phdr[pt_index].p_filesz;
    s_in->vaddr = phdr[pt_index].p_vaddr;

    return 0;
}


void free_segment(struct segment **segment)
{
    if (!segment)
        return;

    struct segment *s;
    if (*segment)
    {
        s = *segment;
        if (s->img)
            free(s->img);
    free(s);
    }
}


char *_get_type(ElfW(Ehdr) ehdr)
{

    switch(ehdr.e_type)
    {
        case ET_NONE:
            return "ET_NONE";
            break;
        case ET_REL:
            return "ET_REL";
            break;
        case ET_EXEC:
            return "ET_EXEC";
            break;
        case ET_DYN:
            return "ET_DYN";
            break;
        case ET_CORE:
            return "ET_CORE";
            break;
        case ET_NUM:
            return "ET_NUM";
            break;
        case ET_LOOS:
            return "ET_LOOS";
            break;
        case ET_HIOS:
            return "ET_HIOS";
            break;
        case ET_LOPROC:
            return "ET_LOPROC";
            break;
        case ET_HIPROC:
            return "ET_HIPROC";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}

/* Get the architecture type from the ELF header*/
char *_get_arch(ElfW(Ehdr) ehdr)
{
    switch(ehdr.e_machine)
    {
        case EM_NONE:
            return "EM_NONE";
            break;
        case EM_M32:
            return "EM_M32";
            break;
        case EM_SPARC:
            return "EM_SPARC";
            break;
        case EM_386:
            return "EM_386";
            break;
        case EM_68K:
            return "EM_68K";
            break;
        case EM_88K:
            return "EM_88K";
            break;
        case EM_860:
            return "EM_860";
            break;
        case EM_MIPS:
            return "EM_MIPS";
            break;
        case EM_S370:
            return "EM_S370";
            break;
        case EM_MIPS_RS3_LE:
            return "EM_MIPS_RS3_LE";
            break;
        case EM_PARISC:
            return "EM_PARISC";
            break;
        case EM_VPP500:
            return "EM_VPP500";
            break;
        case EM_SPARC32PLUS:
            return "EM_SPARC32PLUS";
            break;
        case EM_960:
            return "EM_960";
            break;
        case EM_PPC:
            return "EM_PPC";
            break;
        case EM_PPC64:
            return "EM_PPC64";
            break;
        case EM_S390:
            return "EM_S390";
            break;
        case EM_V800:
            return "EM_V800";
            break;
        case EM_FR20:
            return "EM_FR20";
            break;
        case EM_RH32:
            return "EM_RH32";
            break;
        case EM_RCE:
            return "EM_RCE";
            break;
        case EM_ARM:
            return "EM_ARM";
            break;
        case EM_ALPHA:
            return "EM_ALPHA";
            break;
        case EM_SH:
            return "EM_SH";
            break;
        case EM_SPARCV9:
            return "EM_SPARCV9";
            break;
        case EM_TRICORE:
            return "EM_TRICORE";
            break;
        case EM_ARC:
            return "EM_ARC";
            break;
        case EM_H8_300:
            return "EM_H8_300";
            break;
        case EM_H8_300H:
            return "EM_H8_300H";
            break;
        case EM_H8S:
            return "EM_H8S";
            break;
        case EM_H8_500:
            return "EM_H8_500";
            break;
        case EM_IA_64:
            return "EM_IA_64";
            break;
        case EM_MIPS_X:
            return "EM_MIPS_X";
            break;
        case EM_COLDFIRE:
            return "EM_COLDFIRE";
            break;
        case EM_68HC12:
            return "EM_68HC12";
            break;
        case EM_MMA:
            return "EM_MMA";
            break;
        case EM_PCP:
            return "EM_PCP";
            break;
        case EM_NCPU:
            return "EM_NCPU";
            break;
        case EM_NDR1:
            return "EM_NDR1";
            break;
        case EM_STARCORE:
            return "EM_STARCORE";
            break;
        case EM_ME16:
            return "EM_ME16";
            break;
        case EM_ST100:
            return "EM_ST100";
            break;
        case EM_TINYJ:
            return "EM_TINYJ";
            break;
        case EM_X86_64:
            return "EM_X86_64";
            break;
        case EM_PDSP:
            return "EM_PDSP";
            break;
        case EM_FX66:
            return "EM_FX66";
            break;
        case EM_ST9PLUS:
            return "EM_ST9PLUS";
            break;
        case EM_ST7:
            return "EM_ST7";
            break;
        case EM_68HC16:
            return "EM_68HC16";
            break;
        case EM_68HC11:
            return "EM_68HC11";
            break;
        case EM_68HC08:
            return "EM_68HC08";
            break;
        case EM_68HC05:
            return "EM_68HC05";
            break;
        case EM_SVX:
            return "EM_SVX";
            break;
        case EM_ST19:
            return "EM_ST19";
            break;
        case EM_VAX:
            return "EM_VAX";
            break;
        case EM_CRIS:
            return "EM_CRIS";
            break;
        case EM_JAVELIN:
            return "EM_JAVELIN";
            break;
        case EM_FIREPATH:
            return "EM_FIREPATH";
            break;
        case EM_ZSP:
            return "EM_ZSP";
            break;
        case EM_MMIX:
            return "EM_MMIX";
            break;
        case EM_HUANY:
            return "EM_HUANY";
            break;
        case EM_PRISM:
            return "EM_PRISM";
            break;
        case EM_AVR:
            return "EM_AVR";
            break;
        case EM_FR30:
            return "EM_FR30";
            break;
        case EM_D10V:
            return "EM_D10V";
            break;
        case EM_D30V:
            return "EM_D30V";
            break;
        case EM_V850:
            return "EM_V850";
            break;
        case EM_M32R:
            return "EM_M32R";
            break;
        case EM_MN10300:
            return "EM_MN10300";
            break;
        case EM_MN10200:
            return "EM_MN10200";
            break;
        case EM_PJ:
            return "EM_PJ";
            break;
        case EM_ARC_A5:
            return "EM_ARC_A5";
            break;
        case EM_XTENSA:
            return "EM_XTENSA";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}


const char* d_tag_tostr(ElfW(Sword) d_tag)
{
    switch(d_tag)
    {
        case DT_SYMTAB:
            return "DT_SYMTAB";
            break;
        case DT_SYMENT:
            return "DT_SYMENT";
            break;
        case DT_PLTGOT:
            return "DT_PLTGOT";
            break;
        case DT_STRTAB:
            return "DT_STRTAB";
            break;
        case DT_STRSZ:
            return "DT_STRSZ";
            break;
        case DT_SONAME:
            return "DT_SONAME";
            break;
        case DT_NEEDED:
            return "DT_NEEDED";
            break;
        case DT_HASH:
            return "DT_HASH";
            break;
        case DT_NULL:
            return "DT_NULL";
            break;
        case DT_PLTRELSZ:
            return "DT_PLTRELSZ";
            break;
        case DT_RELA:
            return "DT_RELA";
            break;
        case DT_RELASZ:
            return "DT_RELASZ";
            break;
        case DT_RELAENT:
            return "DT_RELAENT";
            break;
        case DT_INIT:
            return "DT_INIT";
            break;
        case DT_FINI:
            return "DT_FINI";
            break;
        case DT_RPATH:
            return "DT_RPATH";
            break;
        case DT_SYMBOLIC:
            return "DT_SYMBOLIC";
            break;
        case DT_REL:
            return "DT_REL";
            break;
        case DT_RELSZ:
            return "DT_RELSZ";
            break;
        case DT_RELENT:
            return "DT_RELENT";
            break;
        case DT_PLTREL:
            return "DT_PLTREL";
            break;
        case DT_DEBUG:
            return "DT_DEBUG";
            break;
        case DT_TEXTREL:
            return "DT_TEXTREL";
            break;
        case DT_JMPREL:
            return "DT_JMPREL";
            break;
        case DT_BIND_NOW:
            return "DT_BIND_NOW";
            break;
        case DT_INIT_ARRAY:
            return "DT_INIT_ARRAY";
            break;
        case DT_FINI_ARRAY:
            return "DT_FINI_ARRAY";
            break;
        case DT_INIT_ARRAYSZ:
            return "DT_INIT_ARRAYSZ";
            break;
        case DT_FINI_ARRAYSZ:
            return "DT_FINI_ARRAYSZ";
            break;
        case DT_RUNPATH:
            return "DT_RUNPATH";
            break;
        case DT_FLAGS:
            return "DT_FLAGS";
            break;
        case DT_LOPROC:
            return "DT_LOPROC";
            break;
        case DT_HIPROC:
            return "DT_HIPROC";
            break;
        case DT_MIPS_BASE_ADDRESS:
            return "DT_MIPS_BASE_ADDRESS";
            break;
        case DT_MIPS_GOTSYM:
            return "DT_MIPS_GOTSYM";
            break;
        case DT_MIPS_SYMTABNO:
            return "DT_MIPS_SYMTABNO";
            break;
        case DT_MIPS_UNREFEXTNO:
            return "DT_MIPS_UNREFEXTNO";
            break;
        case DT_MIPS_LOCAL_GOTNO:
            return "DT_MIPS_LOCAL_GOTNO";
            break;
        default:
            return "Other";
            break;
    }
}

const char *sh_type_tostr(ElfW(Word) sh_type)
{
    switch(sh_type)
    {
        case SHT_NULL:
            return "SHT_NULL";
            break;
        case SHT_PROGBITS:
            return "SHT_PROGBITS";
            break;
        case SHT_SYMTAB:
            return "SHT_SYMTAB";
            break;
        case SHT_STRTAB:
            return "SHT_STRTAB";
            break;
        case SHT_RELA:
            return "SHT_RELA";
            break;
        case SHT_HASH:
            return "SHT_HASH";
            break;
        case SHT_DYNAMIC:
            return "SHT_DYNAMIC";
            break;
        case SHT_NOTE:
            return "SHT_NOTE";
            break;
        case SHT_NOBITS:
            return "SHT_NOBITS";
            break;
        case SHT_REL:
            return "SHT_REL";
            break;
        case SHT_SHLIB:
            return "SHT_SHLIB";
            break;
        case SHT_DYNSYM:
            return "SHT_DYNSYM";
            break;
        case SHT_INIT_ARRAY:
            return "SHT_INIT_ARRAY";
            break;
        case SHT_FINI_ARRAY:
            return "SHT_FINI_ARRAY";
            break;
        case SHT_PREINIT_ARRAY:
            return "SHT_PREINIT_ARRAY";
            break;
        case SHT_GROUP:
            return "SHT_GROUP";
            break;
        case SHT_SYMTAB_SHNDX:
            return "SHT_SYMTAB_SHNDX";
            break;
        case SHT_LOOS:
            return "SHT_LOOS";
            break;
        case SHT_HIOS:
            return "SHT_HIOS";
            break;
        case SHT_LOPROC:
            return "SHT_LOPROC";
            break;
        case SHT_HIPROC:
            return "SHT_HIPROC";
            break;
        case SHT_LOUSER:
            return "SHT_LOUSER";
            break;
        case SHT_HIUSER:
            return "SHT_HIUSER";
            break;
        case SHT_GNU_ATTRIBUTES:
            return "SHT_GNU_ATTRIBUTES";
            break;
        case SHT_GNU_HASH:
            return "SHT_GNU_HASH";
            break;
        case SHT_GNU_LIBLIST:
            return "SHT_GNU_LIBLIST";
            break;
        case SHT_GNU_verdef:
            return "SHT_GNU_verdef";
            break;
        case SHT_GNU_verneed:
            return "SHT_GNU_verneed";
            break;
        case SHT_ARM_EXIDX:
            return "SHT_ARM_EXIDX";
            break;
        case SHT_ARM_PREEMPTMAP:
            return "SHT_ARM_PREEMPTMAP";
            break;
        case SHT_ARM_ATTRIBUTES:
            return "SHT_ARM_ATTRIBUTES";
            break;
        case SHT_MIPS_REGINFO:
            return "SHT_MIPS_REGINFO";
            break;
        case SHT_MIPS_OPTIONS:
            return "SHT_MIPS_OPTIONS";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}


/* Symbol table : special section index values */
const char *sh_index_tostr(ElfW(Half) ndx)
{
    switch(ndx)
    {
        case SHN_ABS:
            return "SHN_ABS";
            break;
        case SHN_COMMON:
            return "SHN_COMMON";
            break;
        case SHN_UNDEF:
            return "SHN_UNDEF";
            break;


        /* These two are SPARC specific
        case SHN_BEFORE:
            return "SHN_BEFORE";
            break;
        case SHN_AFTER:
            return "SHN_AFTER";
            break;
            */

        /* Duplicate values and interfere with other stuff
        case SHN_LORESERVE:
            return "SHN_LORESERVE";
            break;

        case SHN_LOPROC:
            return "SHN_LOPROC";
            break;
        case SHN_HIPROC:
            return "SHN_HIPROC";
            break;
        case SHN_LOOS:
            return "SHN_LOOS";
            break;
        case SHN_HIOS:
            return "SHN_HIOS";
            break;
            */
        case SHN_XINDEX:
            return "SHN_XINDEX";
            break;


        /* MIPS Stuff */
        case SHN_MIPS_ACOMMON:
            return "SHN_MIPS_ACOMMON";
            break;
        case SHN_MIPS_TEXT:
            return "SHN_MIPS_TEXT";
            break;
        case SHN_MIPS_DATA:
            return "SHN_MIPS_DATA";
            break;
        case SHN_MIPS_SCOMMON:
            return "SHN_MIPS_SCOMMON";
            break;
        case SHN_MIPS_SUNDEFINED:
            return "SHN_MIPS_SUNDEFINED";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}


/* Symbol table: symbol binding */
const char *symb_bind_tostr(int info)
{
    switch(info)
    {
        case STB_LOCAL:
            return "STB_LOCAL";
            break;
        case STB_GLOBAL:
            return "STB_GLOBAL";
            break;
        case STB_WEAK:
            return "STB_WEAK";
            break;
        case STB_LOPROC:
            return "STB_LOPROC";
            break;
        default:
            return "N/A";
            break;
    }
}

/* Symbol table: symbol type */
const char* symb_type_tostr(int type)
{
    switch(type)
    {
        case STT_NOTYPE:
            return "STT_NOTYPE";
            break;
        case STT_OBJECT:
            return "STT_OBJECT";
            break;
        case STT_FUNC:
            return "STT_FUNC";
            break;
        case STT_SECTION:
            return "STT_SECTION";
            break;
        case STT_FILE:
            return "STT_FILE";
            break;
        case STT_LOPROC:
            return "STT_LOPROC";
            break;
        case STT_HIPROC:
            return "STT_HIPROC";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}


const char * pt_type_tostr(ElfW(Word) p_type)
{
    switch(p_type)
    {
        case(PT_NULL):
            return "PT_NULL";
            break;
        case(PT_LOAD):
            return "PT_LOAD";
            break;
        case(PT_DYNAMIC):
            return "PT_DYNAMIC";
            break;
        case(PT_INTERP):
            return "PT_INTERP";
            break;
        case(PT_NOTE):
            return "PT_NOTE";
            break;
        case(PT_SHLIB):
            return "PT_SHLIB";
            break;
        case(PT_PHDR):
            return "PT_PHDR";
            break;
        case(PT_TLS):
            return "PT_TLS";
            break;
        case(PT_LOOS):
            return "PT_LOOS";
            break;
        case(PT_HIOS):
            return "PT_HIOS";
            break;
        case(PT_LOPROC):
            return "PT_LOPROC";
            break;
        case(PT_HIPROC):
            return "PT_HIPROC";
            break;
        case(PT_GNU_EH_FRAME):
            return "PT_GNU_EH_FRAME";
            break;
        case(PT_GNU_STACK):
            return "PT_GNU_STACK";
            break;
        case(PT_GNU_RELRO):
            return "PT_GNU_RELRO";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}

const char* reloc_type_tostr_68k(unsigned char type)
{
    switch(type)
    {
        case R_68K_NONE:
            return "R_68K_NONE";
            break;
        case R_68K_32:
            return "R_68K_32";
            break;
        case R_68K_16:
            return "R_68K_16";
            break;
        case R_68K_8:
            return "R_68K_8";
            break;
        case R_68K_PC32:
            return "R_68K_PC32";
            break;
        case R_68K_PC16:
            return "R_68K_PC16";
            break;
        case R_68K_PC8:
            return "R_68K_PC8";
            break;
        case R_68K_GOT32:
            return "R_68K_GOT32";
            break;
        case R_68K_GOT16:
            return "R_68K_GOT16";
            break;
        case R_68K_GOT8:
            return "R_68K_GOT8";
            break;
        case R_68K_GOT32O:
            return "R_68K_GOT32O";
            break;
        case R_68K_GOT16O:
            return "R_68K_GOT16O";
            break;
        case R_68K_GOT8O:
            return "R_68K_GOT8O";
            break;
        case R_68K_PLT32:
            return "R_68K_PLT32";
            break;
        case R_68K_PLT16:
            return "R_68K_PLT16";
            break;
        case R_68K_PLT8:
            return "R_68K_PLT8";
            break;
        case R_68K_PLT32O:
            return "R_68K_PLT32O";
            break;
        case R_68K_PLT16O:
            return "R_68K_PLT16O";
            break;
        case R_68K_PLT8O:
            return "R_68K_PLT8O";
            break;
        case R_68K_COPY:
            return "R_68K_COPY";
            break;
        case R_68K_GLOB_DAT:
            return "R_68K_GLOB_DAT";
            break;
        case R_68K_JMP_SLOT:
            return "R_68K_JMP_SLOT";
            break;
        case R_68K_RELATIVE:
            return "R_68K_RELATIVE";
            break;
        case R_68K_TLS_GD32:
            return "R_68K_TLS_GD32";
            break;
        case R_68K_TLS_GD16:
            return "R_68K_TLS_GD16";
            break;
        case R_68K_TLS_GD8:
            return "R_68K_TLS_GD8";
            break;
        case R_68K_TLS_LDM32:
            return "R_68K_TLS_LDM32";
            break;
        case R_68K_TLS_LDM16:
            return "R_68K_TLS_LDM16";
            break;
        case R_68K_TLS_LDM8:
            return "R_68K_TLS_LDM8";
            break;
        case R_68K_TLS_LDO32:
            return "R_68K_TLS_LDO32";
            break;
        case R_68K_TLS_LDO16:
            return "R_68K_TLS_LDO16";
            break;
        case R_68K_TLS_LDO8:
            return "R_68K_TLS_LDO8";
            break;
        case R_68K_TLS_IE32:
            return "R_68K_TLS_IE32";
            break;
        case R_68K_TLS_IE16:
            return "R_68K_TLS_IE16";
            break;
        case R_68K_TLS_IE8:
            return "R_68K_TLS_IE8";
            break;
        case R_68K_TLS_LE32:
            return "R_68K_TLS_LE32";
            break;
        case R_68K_TLS_LE16:
            return "R_68K_TLS_LE16";
            break;
        case R_68K_TLS_LE8:
            return "R_68K_TLS_LE8";
            break;
        case R_68K_TLS_DTPMOD32:
            return "R_68K_TLS_DTPMOD32";
            break;
        case R_68K_TLS_DTPREL32:
            return "R_68K_TLS_DTPREL32";
            break;
        case R_68K_TLS_TPREL32:
            return "R_68K_TLS_TPREL32";
            break;
        case R_68K_NUM:
            return "R_68K_NUM";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}

const char* reloc_type_tostr_386(unsigned char type)
{
    switch(type)
    {
        case R_386_NONE:
            return "R_386_NONE";
            break;
        case R_386_32:
            return "R_386_32";
            break;
        case R_386_PC32:
            return "R_386_PC32";
            break;
        case R_386_GOT32:
            return "R_386_GOT32";
            break;
        case R_386_PLT32:
            return "R_386_PLT32";
            break;
        case R_386_COPY:
            return "R_386_COPY";
            break;
        case R_386_GLOB_DAT:
            return "R_386_GLOB_DAT";
            break;
        case R_386_JMP_SLOT:
            return "R_386_JMP_SLOT";
            break;
        case R_386_RELATIVE:
            return "R_386_RELATIVE";
            break;
        case R_386_GOTOFF:
            return "R_386_GOTOFF";
            break;
        case R_386_GOTPC:
            return "R_386_GOTPC";
            break;
        case R_386_32PLT:
            return "R_386_32PLT";
            break;
        case R_386_TLS_TPOFF:
            return "R_386_TLS_TPOFF";
            break;
        case R_386_TLS_IE:
            return "R_386_TLS_IE";
            break;
        case R_386_TLS_GOTIE:
            return "R_386_TLS_GOTIE";
            break;
        case R_386_TLS_LE:
            return "R_386_TLS_LE";
            break;
        case R_386_TLS_GD:
            return "R_386_TLS_GD";
            break;
        case R_386_TLS_LDM:
            return "R_386_TLS_LDM";
            break;
        case R_386_16:
            return "R_386_16";
            break;
        case R_386_PC16:
            return "R_386_PC16";
            break;
        case R_386_8:
            return "R_386_8";
            break;
        case R_386_PC8:
            return "R_386_PC8";
            break;
        case R_386_TLS_GD_32:
            return "R_386_TLS_GD_32";
            break;
        case R_386_TLS_GD_PUSH:
            return "R_386_TLS_GD_PUSH";
            break;
        case R_386_TLS_GD_CALL:
            return "R_386_TLS_GD_CALL";
            break;
        case R_386_TLS_GD_POP:
            return "R_386_TLS_GD_POP";
            break;
        case R_386_TLS_LDM_32:
            return "R_386_TLS_LDM_32";
            break;
        case R_386_TLS_LDM_PUSH:
            return "R_386_TLS_LDM_PUSH";
            break;
        case R_386_TLS_LDM_CALL:
            return "R_386_TLS_LDM_CALL";
            break;
        case R_386_TLS_LDM_POP:
            return "R_386_TLS_LDM_POP";
            break;
        case R_386_TLS_LDO_32:
            return "R_386_TLS_LDO_32";
            break;
        case R_386_TLS_IE_32:
            return "R_386_TLS_IE_32";
            break;
        case R_386_TLS_LE_32:
            return "R_386_TLS_LE_32";
            break;
        case R_386_TLS_DTPMOD32:
            return "R_386_TLS_DTPMOD32";
            break;
        case R_386_TLS_DTPOFF32:
            return "R_386_TLS_DTPOFF32";
            break;
        case R_386_TLS_TPOFF32:
            return "R_386_TLS_TPOFF32";
            break;
        case R_386_TLS_GOTDESC:
            return "R_386_TLS_GOTDESC";
            break;
        case R_386_TLS_DESC_CALL:
            return "R_386_TLS_DESC_CALL";
            break;
        case R_386_TLS_DESC:
            return "R_386_TLS_DESC";
            break;
        case R_386_IRELATIVE:
            return "R_386_IRELATIVE";
            break;
        case R_386_NUM:
            return "R_386_NUM";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}

char *ei_data_tostr(unsigned char val)
{
    switch (val) 
    {
        case ELFDATA2LSB:
            return "LSB";
            break;
        case ELFDATA2MSB:
            return "MSB";
            break;
        case ELFDATANONE:
            return "INVALID";
            break;
        default:
            return "CLE_UNK";
            break;
    }
}
