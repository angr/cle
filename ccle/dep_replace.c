#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <string.h>
#include "libcle.h"

/* Checks whether library name @name is actually required by the binary 
 * If it is, returns the offset of the string in the string table.
 * If not, returns 0
 * */
ElfW(Addr) check_needed(ElfW(Dyn) *dynamic, struct segment *s, lib_orig)
{
    int i;
    char *strtab;
    char *lib_found;

    strtab = get_strtab_ptr(dynamic, s);
    if (!strtab){
        printf("ERR: NOSTRTAB");
        return;
    }

    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
    {
        if (dynamic[i].d_tag == DT_NEEDED)
        {
            lib_found = &strtab[dynamic[i].d_un.d_ptr];
            if (strcmp(lib_found, lib_orig) == 0)
                return dynamic[i].d_un.d_ptr;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    char *binary;
    char *lib_orig;
    char *lib_repl;
    unsigned char *text, *strtab, *vaddr;
    int str_off;

    /* Parameters:
     *  - name of the binary to modify
     *  - name of a library that it depends on
     *  - name of the new library to replace it with
     */

    if (argc < 4)
    {
        printf("Usage: dep_replace <binary> <lib_name> <replacement_lib_name>\n");
        return(EXIT_FAILURE);
    }

    binary = argv[1];
    lib_orig = argv[2];
    lib_repl = argv[3];

    if (strlen(lib_orig) < strlen(lib_repl))
    {
        printf("Come on dude, gimme a lib name *at most* as long as the one you "
                "want to replace !");
        return(EXIT_FAILURE);
    }

    /* We're not crazy enough to shift all the binary */
    printf("--> All right, let's replace %s by %s in %s...\n",
            lib_orig, lib_repl, binary);


    return(EXIT_SUCCESS);

    f = fopen(binfile,"r");
    if (!f)
    {
        printf("Could not open file.\n");
        exit(EXIT_FAILURE);
    }

    /* Determine the architecture type*/
    if ((get_elf_class(f) != ELFCLASS64) && (get_elf_class(f) != ELFCLASS32))
    {
        printf("Invalid ELF file !\n");
        exit(EXIT_FAILURE);
    }

    /* Get ELF header*/
    rewind(f);
    fread(&ehdr, sizeof(Elf64_Ehdr), 1, f);

    phdr = get_phdr(ehdr, f);
    dynamic = get_dynamic(phdr, ehdr.e_phnum, f);

    /* Map the text segment */
    for (i = 0; i < phdr.e_phnum, i++)
    {
        if(phdr[i].p_memsz == phdr[i].p_filesz)
        {
            vaddr = phdr[i].p_vaddr;
            text = mmap(vaddr, phdr[i].filesz, PROT_READ || PROT_WRITE,
                    MAP_SHARED, f, phdr[i].p_offset);
        }
    }

    /* Where is the strtab */
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
        if (dynamic[i].d_tag == DT_STRTAB)
            strtab = dynamic[i].d_un.d_ptr;

    str_off = strtab - vaddr;
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
        if (dynamic[i].d_tag == DT_NEEDED)

    /* DT_NEEDED */


    fclose(f);
    free(phdr);
    free(shdr);
}
