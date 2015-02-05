#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include "cle.h"
#include "libcle_static.h"
#include "libcle.h"


/* Cle_static: get information from Elf sections (as opposed to Elf segments)
 */




/* Load the section header string table into memory and return a pointer to it
 *	@Ehdr: the Elf header
 *	@shdr: a pointer to the section header table
	@f: the elf file's descriptor

	Note: this is the only strtab that is generally not part of the address
	space of the process (at least to what I've seen in practice. The Elf spec
	doesn't say anything about it*/

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

/* SHT_SYMTAB is the symbol table we get from sections, which is not part of
 * the memory of the process (but is present in the file when it is not stripped) */
ElfW(Sym)* alloc_load_sht_symtab(ElfW(Shdr) *shdr, ElfW(Half) sh_size, FILE *f)
{
	int i, rd;
	ElfW(Sym)* symtab;

	// Get the symtab index
	for (i=0; i<sh_size; i++)
		if (shdr[i].sh_type == SHT_SYMTAB)
			break;

	if (shdr[i].sh_type != SHT_SYMTAB)
	{
		printf("No sht_symtab in this binary. Stripped ?\n");
		return NULL;
	}

	if(shdr[i].sh_size == 0)
		return NULL;

	symtab = malloc(shdr[i].sh_size);
	if (!symtab){
		printf("Could not allocate memory (%s)\n", __func__);
		return NULL;
	}

	fseek(f, shdr[i].sh_offset, SEEK_SET);
	rd = fread(symtab, shdr[i].sh_size, 1, f);
	if (rd == 0)
	{
		printf("Error %d while reading file descriptor (%s)\n", rd, __func__);
		free(symtab);
		return NULL;
	}
	return symtab;
}

/* Simply print strings of @strtab 
 * TODO: put that somewhere else
 * */
void print_strtab(const char*name, char* strtab, size_t strsz)
{
	int i, eos;

	if(!strtab)
	{
		printf("No strtab :( (%s)\n", __func__);
		return;
	}

	printf("STRTAB, OFFSET, STR\n---\n");
	for(i=0; i<strsz; i++)
	{
		if (strtab[i] == '\0')
		{
			if (eos == 0)
			{
				eos=1;
				printf("\n%s, 0x%x, ", name, i);
			}
			else
				continue;
		}
		else
		{
			printf("%c", strtab[i]);
			eos=0;
		}
	}
	printf("\n");
}


/* As there might be multiple string tables into the same binary, we scan for
 * such entries in the section headers, and print the according tables when
 * found. To distinguish between tables, we name them strtab%d where %d is the
 * index in the section headers */
void print_static_strtabs(ElfW(Shdr) *shdr, int sh_size, struct segment *text, struct segment *data)
{
	int i;
	size_t size;
	char *ptr;
	char *name;
	const char *base = "s_strtab";

	name = malloc(sizeof(char) * 10);

	for(i=0; i<sh_size; i++)
	{
		if (shdr[i].sh_type == SHT_STRTAB)
		{
			ptr = (char*) get_ptr(shdr[i].sh_addr, text, data);
			size = shdr[i].sh_size;
			if (ptr)
			{
				sprintf(name, "%s%d", base, i);
#ifdef ELF64
				printf("\nStatic strtab @0x%lx\n", shdr[i].sh_addr);
#else
				printf("\nStatic strtab @0x%x\n", (unsigned int) shdr[i].sh_addr);
#endif
				print_strtab(name, ptr, size);
			}
		}
	}

	free(name);
}

void print_static_symtab(ElfW(Shdr) *shdr, int sh_size, ElfW(Sym) *symtab, FILE *f)
{
	int i, lastindex,strindex;
	//int lastlocal;
	char *strtab;

	if(!symtab)
	{
		printf("No symtab to print (%s)\n", __func__);
		return;
	}
	/* Find out symbol table index*/
	for(i=0; i<sh_size; i++)
		if (shdr[i].sh_type == SHT_SYMTAB)
			break;

	/* Get the last index of local symbol*/
	//lastlocal = shdr[i].sh_info;

	/* End of the symbol table*/
	lastindex = shdr[i].sh_size / sizeof(ElfW(Sym));

	/* Index of the associated string table */
	strindex = shdr[i].sh_link;

	strtab = (char *)alloc_load_static_section(shdr, strindex, f);
	_print_symtab(symtab, lastindex, strtab);

}


/* Generic print symtab - local to this module 
 * TODO: use in dynamic related code
 * */
void _print_symtab(ElfW(Sym) *symtab, int lastindex, char *strtab)
{
	int i;
    unsigned char type_v, bind_v;
    const char *type_s, *bind_s, *shn_type, *name;

	if(!strtab || !symtab)
	{
		printf("No strtab or symtab :( (%s)\n", __func__);
		return;
	}


    printf("\nSYMTAB, VALUE, SIZE, BIND, TYPE, SHTYPE, NAME\n---\n");
	for (i=0; i<lastindex; i++)
	{

		type_v = ST_TYPE(symtab[i].st_info);
		bind_v = ST_BIND(symtab[i].st_info);


		bind_s = symb_bind_tostr(bind_v);
		type_s = symb_type_tostr(type_v);

		shn_type = sh_index_tostr(symtab[i].st_shndx);

		name = &strtab[symtab[i].st_name];

#ifdef ELF64
		printf("s_symtab, 0x%lx, 0x%lx, %s, %s, %s, %s\n", symtab[i].st_value,
				symtab[i].st_size, bind_s, type_s, shn_type, name);
#else
		printf("s_symtab, 0x%x, 0x%x, %s, %s, %s, %s\n", (unsigned int) symtab[i].st_value,
				(unsigned int) symtab[i].st_size, bind_s, type_s, shn_type, name);
#endif
	}

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

	if(!sht_strtab)
		printf("No section header strtab :( (%s)\n", __func__);

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


/* Get a pointer to the location of vaddr in the corresponding segment, where
 * we loaded it in memory (which doesn't correspond to the actual vaddresses,
 * those are real addresses in our mallocated stuff TODO: put that somewhere
 * else, and refactor dynamic related stuff
 * */
void *get_ptr(ElfW(Addr) vaddr, struct segment *text, struct segment *data)
{
	struct segment *s;
	ElfW(Off) off;

	if(vaddr == 0)
		return NULL;

	if (addr_belongs_to_segment(vaddr, text))
		s = text;
	else if (addr_belongs_to_segment(vaddr, data))
		s = data;
	else
		return NULL;

	off = addr_offset_from_segment(vaddr, s);

	if(off == 0)
		return NULL;

	return s->img + off;
}

/* This allocates memory and loads the given section into memory 
 * @ shdr: the section header table
 * @index: the index in the section headers table
 * f: the file descriptor of the Elf file
 * */
void *alloc_load_static_section (ElfW(Shdr) *shdr, size_t index, FILE *f)
{
	int rd;
	void *ptr;

	ptr = malloc(shdr[index].sh_size);
	if (!ptr){
		printf("Could not allocate memory (%s)\n", __func__);
		return NULL;
	}

	fseek(f, shdr[index].sh_offset, SEEK_SET);
	rd = fread(ptr, shdr[index].sh_size, 1, f);
	if (rd == 0)
	{
		printf("Error %d while reading file descriptor (%s)\n", rd, __func__);
		return NULL;
	}
	return ptr;
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


