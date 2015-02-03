#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include "cle.h"
#include "libcle_static.h"


/* Cle_static: get information from Elf sections (as opposed to Elf segments)
 */




/* Load the section header string table into memory and return a pointer to it
 *	@Ehdr: the Elf header
 *	@shdr: a pointer to the section header table
	@f: the elf file's descriptor
*/

char* alloc_load_sht_strtab(ElfW(Ehdr) ehdr, ElfW(Shdr) *shdr, FILE *f)
{
	ElfW(Off) offset;
	ElfW(Word) size;
	int shstrndx, rd;
	char * sh_strtab;

	shstrndx = ehdr.e_shstrndx;
	offset = shdr[shstrndx].sh_offset;
	size = shdr[shstrndx].sh_size;

	sh_strtab = malloc(size * sizeof(char));
	if (!sh_strtab)
	{
		printf("Could not allocate string buffer (%s)\n", __func__);
		return NULL;
	}

	fseek(f, offset, SEEK_SET);

	/* Read p_filesz bytes from file */
	rd = fread(sh_strtab, size, 1, f);
	if (rd == 0)
	{
		printf("Error %d while reading file descriptor (%s)\n", rd, __func__);
		return NULL;
	}
	return sh_strtab;
}


/* Get the section header table */
ElfW(Shdr) *get_shdr(ElfW(Ehdr) ehdr, FILE *f)
{
    int i;
    ElfW(Shdr) *shdr;

    if (ehdr.e_shnum == 0)
        return NULL;

    /* Read the section header table*/
    shdr = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    if (!shdr)
	{
		printf("Could not allocate memory (%s)\n", __func__);
        return NULL;
	}

    for (i = 0; i < ehdr.e_shnum; i++)
    {
        fseek(f, ehdr.e_shoff + (i * ehdr.e_shentsize), SEEK_SET);
        fread(&shdr[i], ehdr.e_shentsize, 1, f);
    }

    return shdr;
}


/* Print the section header table if it is there */
void print_shdr(ElfW(Shdr) *shdr, int shdr_size, char* sht_strtab)
{

	int i;

    printf("\nSHDR, NAME, OFFSET, ADDR, SIZE, TYPE\n---\n");

	/* Here, we start from 1 as the first row is always NULL values */
    for (i = 1; i < shdr_size; i++)
    {
#ifdef ELF64
        printf("shdr, %s, 0x%lx, 0x%lx, 0x%lx, %s\n", get_str(sht_strtab, shdr[i].sh_name), 
				shdr[i].sh_offset,
                shdr[i].sh_addr, shdr[i].sh_size,
                sh_type_tostr(shdr[i].sh_type)); 
#else
        printf("shdr, %s, 0x%x, 0x%x, 0x%x, %s\n", get_str(sht_strtab, shdr[i].sh_name), 
				(unsigned int) shdr[i].sh_offset,
                (unsigned int) shdr[i].sh_addr, (unsigned int) shdr[i].sh_size,
                sh_type_tostr(shdr[i].sh_type)); 
#endif

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


