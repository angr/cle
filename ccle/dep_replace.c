#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <string.h>
#include "libcle.h"

/* Checks whether library name @name is actually required by the binary */
void check_needed(ElfW(Dyn) *dynamic, struct segment *s)
{
    int i;
    char *strtab;

    strtab = get_strtab_ptr(dynamic, s);
    if (!strtab){
        printf("ERR: NOSTRTAB");
        return;
    }

    printf("needed");
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
    {
        if (dynamic[i].d_tag == DT_NEEDED)
            printf(", %s", &strtab[dynamic[i].d_un.d_ptr]);
    }
    printf("\n");
}
int main(int argc, char **argv)
{
    char *binary;
    char *lib_orig;
    char *lib_repl;

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
    print_basic_info(ehdr);

    /* Get program header table*/
    phdr = get_phdr(ehdr, f);
    print_phdr(phdr, ehdr.e_phnum);

    dynamic = get_dynamic(phdr, ehdr.e_phnum, f);
    print_dynamic(dynamic);

    data = malloc(sizeof(struct segment));
    text = malloc(sizeof(struct segment));

    if(!data || !text)
        exit(EXIT_FAILURE);

    if (load_text(ehdr, phdr, text, f) != 0)
        exit(EXIT_FAILURE);

    if (load_data(ehdr, phdr, data, f) != 0)
        exit(EXIT_FAILURE);

    check_needed(dynamic, text, lib_orig);

    fclose(f);
    free(phdr);
    free(shdr);
    free_segment(&data);
    free_segment(&text);
}
