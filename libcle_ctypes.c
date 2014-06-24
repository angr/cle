#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <string.h>
#include "libcle.h"

#define MAX_SO 30

/* libCLÉ extracts information from ELF dynamic sections.
 * This code assumes that the binary file has been stripped, and that the
 * section header has been removed.
 *
 * This is meant to be used as a CTYPES library.
 */

FILE *f;
ElfW(Ehdr) ehdr;
ElfW(Phdr) *phdr;
ElfW(Dyn) *dynamic;
ElfW(Addr) strtab_vaddr;
int *so_off;

void __attribute ((destructor)) __unload_file()
{
    /* It sucks to allocate and free memory into a library, but here we need to
     * hide low level constructs from python, so there is no choice. This is
     * what distinguishes licle_ctypes from libcle */
    if(f) fclose(f);
    free(phdr);
    free(so_off);
    free(dynamic);
}

int __load_file(const char*path)
{
 /* Load the binary file
 * Returns:
 *      0 on success
 :*      -ENOENT if no such file exists
 *      -EINVAL if the file is not a valid ELF file
 *      -ENODA if there is no program header
 *      -EOPNOTSUP if there is no dynamic section
 * */

    size_t count;

    //__unload_file(f);

    f = fopen(path, "r");
    if (!f)
        return -ENOENT; // No such file or directory

    if ((get_elf_class(f) != ELFCLASS64) && (get_elf_class(f) != ELFCLASS32))
        return -EINVAL; // Invalid argument

    /* Load the ELF program header*/
    rewind(f);
    count = fread(&ehdr, sizeof(Elf64_Ehdr), 1, f);

    if (count <= 0)
        return count;

    if (!(phdr = get_phdr(ehdr, f)))
        return -ENODATA; // No data available

    if (!(dynamic = get_dynamic(phdr, ehdr.e_phnum, f)))
        return -EOPNOTSUPP; // Operation not supported

    return 0;
}

int get_entry_point()
{
    return ehdr.e_entry;
}

int get_base_addr()
{
    //ElfW(Phdr) *phdr;
    ElfW(Addr) vaddr;
    int i;

    if (!phdr)
        return -ENOMEM;

    /* The base address is the lowest virtual address of PT_LOAD segments,
     * truncated to the nearest multiple of the maximum page size */
    for (i=0; i<ehdr.e_phnum; i++)
        if (phdr[i].p_vaddr < vaddr && phdr[i].p_vaddr > 0)
            vaddr = phdr[i].p_vaddr;
    return vaddr;
}

char *get_symbol_name(int i);
char *get_symbol_type(int i);


/* ### Text segment information ### */

ElfW(Addr) get_text_vaddr()
{
    int i;
    if ((i = find_text_index(ehdr, phdr)))
        return phdr[i].p_vaddr;
    return i;
}

ElfW(Off) get_text_offset()
{
    int i;
    if ((i = find_text_index(ehdr, phdr)))
        return phdr[i].p_offset;
    return i;
}

ElfW(Word) get_text_filesz()
{
    int i;
    if ((i = find_text_index(ehdr, phdr)))
        return phdr[i].p_filesz;
    return i;
}


/* ### Data segment information ### */
ElfW(Addr) get_data_vaddr()
{
    int i;
    if ((i = find_data_index(ehdr, phdr)))
        return phdr[i].p_vaddr;
    return i;
}

ElfW(Off) get_data_offset()
{
    int i;
    if ((i = find_data_index(ehdr, phdr)))
        return phdr[i].p_offset;
    return i;
}

ElfW(Word) get_data_filesz()
{
    int i;
    if ((i = find_data_index(ehdr, phdr)))
        return phdr[i].p_filesz;
    return i;
}

ElfW(Word) get_data_memsz()
{
    int i;
    if ((i = find_data_index(ehdr, phdr)))
        return phdr[i].p_memsz;
    return i;
}


/* ## Dependency information ## */

/* How many shared libraries does this binary depend on ? */
int get_num_libs()
{
    int i, j=0;
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
        if(dynamic[i].d_tag == DT_NEEDED)
            j++;
    return j;
}

/* Get the offset of lib number @no in the string table*/
int *get_lib_names_offsets()
{
    int i, j=0, sz;
    sz = get_num_libs();
    so_off = malloc(sizeof(int) * sz);

    if (!so_off || sz == 0)
        return NULL;

    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
        if(dynamic[i].d_tag == DT_NEEDED)
        {
            so_off[j] = dynamic[i].d_un.d_val;
            j++;
        }
    return so_off;
}

/* ## Stub functions to libcle ## */
inline char *get_arch()
{
    return _get_arch(ehdr);
}

inline int get_strtab_sz()
{
    return _get_strtab_sz(dynamic);
}

inline int get_strtab_vaddr()
{
    return _get_strtab_vaddr(dynamic);
}


