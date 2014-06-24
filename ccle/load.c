#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <string.h>
#include "libcle.h"


/* Functions declared in this module */
void print_phdr (ElfW(Phdr) *phdr, size_t size);
ElfW(Shdr) *get_shdr(ElfW(Ehdr) ehdr, FILE *f);
char *get_dyn_real_addr(ElfW(Dyn) *dynamic, ElfW(Sword) d_tag);
//ElfW(Dyn) *get_dyn(ElfW(Phdr) *phdr, int count, FILE *f);
//ElfW(Sym) *get_symtab_ptr(ElfW(Dyn) *dynamic);
ElfW(Rela) *get_rela_ptr(ElfW(Dyn) *dynamic);
//size_t guess_symtab_sz(ElfW(Dyn) *dynamic);

/* Same thing with elf data types.*/

struct segment *text_seg, *data_seg;

/* Print, in ASCII form, the load segment the address belongs to*/
const char* which_segment(ElfW(Addr) address)
{
    if (addr_belongs_to_segment(address, data_seg))
        return "DATA";
    else if (addr_belongs_to_segment(address, text_seg))
        return "TEXT";
    return NULL;
}

/* Gets the offset of vaddr from segment's vaddr
 * */
int segment_offset(ElfW(Addr) vaddr)
{
    int offset;
    struct segment *seg;

    if (addr_belongs_to_segment(vaddr, data_seg))
        seg = data_seg;
    else if (addr_belongs_to_segment(vaddr, text_seg))
        seg = text_seg;
    else
        return -1;

    offset = (vaddr - seg->vaddr);
    return offset;
}


/* Gets the real address of the string table,
 * i.e., where we loaded it 
 * TODO: we assume that it is in the text segment, might not be safe
 * */
char *get_strtab_raddr(ElfW(Dyn) *dynamic)
{
    ElfW(Addr) vaddr;
    ElfW(Word) offset;

    vaddr = _get_symtab_vaddr(dynamic);
    offset = vaddr - text_seg->vaddr;
    return (char*) (text_seg->img + offset);
}


/* Prints the string table*/
void print_strtab(ElfW(Dyn) *dynamic)
{
    ElfW(Word) size, offset;
    ElfW(Addr) vaddr;
    int i, otherchar = 0, nullchar = 0;
    char c, *p;

    vaddr = _get_strtab_vaddr(dynamic);
    size = _get_strtab_sz(dynamic);

    printf("--- String table ---\n");
    if (size == -1 || vaddr == -1)
    {
        printf("ERROR, string table has no address or offset in .text\n");
        return;
    }
    else
        printf("\tsize: %hx - @vaddr %#lx\n", size, vaddr);
    if (!addr_belongs_to_segment(vaddr, text_seg)){
        printf("\tThe string table is not in .text, wtf ??\n");
        return;
    }

    if ((vaddr + size) > (text_seg->vaddr + text_seg->memsz)){
        printf("\tThe string table does NOT fit in .text, wtf ??\n");
        return;
    }

    /* Offset of the string table in .text*/
    offset = vaddr - text_seg->vaddr;

    /* Address of the string table in memory (relative to the text segment).
     * Note that our local load address does not match the virtual address
     * specified in the ELF headers.
     * */
    p = (char*) (text_seg->img + offset);

    for (i=0; i<size; i++)
    {
        c = p[i];
        if(c == '\0')
            nullchar ++;
        else
            otherchar ++;

    printf("\tStats: the string table contains %d null characters and %d non null"
            "characters\n\n", nullchar, otherchar);
    return;
}


/* This function finds the REAL (not virtual) address of the section denoted by
 * d_tag in the Dynamic segment. The returned pointer is an address inside the
 * loaded DATA or TEXT segment. */
char *get_dyn_real_addr(ElfW(Dyn) *dynamic, ElfW(Sword) d_tag)
{

    int i = 0;
    ElfW(Addr) vaddr = -1, offset;
    //ElfW(Word) val = -1;
    struct segment *segment;

    /* Find vaddr and size */
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
        if (dynamic[i].d_tag == d_tag)
            vaddr = dynamic[i].d_un.d_ptr;

    vaddr = get_dyn_ptr_addr(dynamic, d_tag);
    if(vaddr == (ElfW(Addr)) -ENOMEM) // vaddr is unsigned
        return NULL;

    /* Find which segment it belongs to*/
    if (addr_belongs_to_segment(vaddr, text_seg))
        segment = text_seg;
    else if (addr_belongs_to_segment(vaddr, data_seg))
        segment = data_seg;
    else
    {
        printf("ERROR: section type %s does not belong to any loadable segment"
                ":(\n", d_tag_tostr(d_tag));
        return NULL;
    }

    offset = vaddr - segment->vaddr;
    return (char*)(segment->img + offset);
}


/* Gets the REAL address of the DT_RELA relocation table*/
ElfW(Rela) *get_rela_ptr(ElfW(Dyn) *dynamic)
{
    char *addr;
    addr = get_dyn_real_addr(dynamic, DT_RELA);
    return (ElfW(Rela)*) addr;
}

/* Get the total size of the DT_RELA relocation table*/
ElfW(Word) get_rela_sz(ElfW(Dyn) *dynamic)
{
    ElfW(Word) val;
    val = get_dyn_val(dynamic, DT_RELASZ);
    return val;
}

/* This returns a pointer (real address) to the symbol table, contained in the text semgment.
 * No memory is allocated */

ElfW(Sym) *get_symtab_ptr(ElfW(Dyn) *dynamic)
{
    int i = 0;
    ElfW(Addr) vaddr = -1, offset;
    ElfW(Word) size = -1;

    ElfW(Sym) *symtab;

    /* Find vaddr and size */
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
    {
        if (dynamic[i].d_tag == DT_SYMTAB)
            vaddr = dynamic[i].d_un.d_ptr;

        else if (dynamic[i].d_tag == DT_SYMENT)
            size = dynamic[i].d_un.d_val;
    }


    if(vaddr == -1 || size == -1)
    {
        printf("Error: no symbol table address or size\n");
        return NULL;
    }

    if (!addr_belongs_to_segment(vaddr, text_seg))
        return NULL;

    if ((vaddr + size) > text_seg->vaddr + text_seg->memsz)
        return NULL;

    offset = vaddr - text_seg->vaddr;

    symtab = (ElfW(Sym)*) (text_seg->img + offset);

    return symtab;

}

/* The hash table contains ElfW(Word) objects 
 * TODO: rewrite this
 * */
ElfW(Word) *get_hash_table(ElfW(Addr) offset, FILE *f)
{
    size_t total;
    /* The number of symbol table entries should equal nchain, according to the
     * ELF spec */
    ElfW(Word) nbucket, nchain, *hash_table;

    fseek(f, offset, SEEK_SET);
    fread(&nbucket, sizeof(ElfW(Word)), 1, f);
    fread(&nchain, sizeof(ElfW(Word)), 1, f);
    printf("--- Hash table ---\n");
    printf("\t nbucket: %d, nchain: %d\n", nbucket, nchain);

    /* The total size of the hashtable
     * +2 because nbucket and nchain are the two first entries of the table
     * */
    total = (nbucket + nchain + 2) * sizeof(ElfW(Word));
    hash_table = malloc(total);
    if (!hash_table){
        printf("ERROR: could not allocate memory\n");
        return NULL;
    }
    else
        printf("\t allocated %lu bytes to store the hash table\n", total);

    fseek(f, offset, SEEK_SET);
    fread(hash_table, total, 1, f);

    return hash_table;
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


/* Just print the program header table */
void print_phdr (ElfW(Phdr) *phdr, size_t size)
{
    int i;
    const char *name;

    printf("# --- Program header table | %lu entries ---\n", size);
    if (!phdr || size == 0)
    {
        printf("# (Empty)\n");
        return;
    }

    printf("#\t IDX \tOFFSET \t\tVIRT ADDR \tSIZE(disk) \tSIZE(mem) \tALIGN \t\tTYPE\n");

    for (i = 0; i < size; i++){
        name = pt_type_tostr(phdr[i].p_type);
        printf("PHDR_TBL \t%d \t0x%06lx \t0x%06lx \t0x%06lx \t0x%06lx, \t0x%06lx, \t0x%08x \t%s\n", i, phdr[i].p_offset,
                phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz,
                phdr[i].p_align, phdr[i].p_type, name);
    }
    printf("\n");
}

/* Get the section header table */
ElfW(Shdr) *get_shdr(ElfW(Ehdr) ehdr, FILE *f)
{
    int i;
    ElfW(Shdr) *shdr;

    /* Read the section header table*/
    shdr = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    printf("#---Section header table | %d entries ---\n", ehdr.e_shnum);

    if (ehdr.e_shnum == 0)
        printf("#\tThis file contains no section headers. Stripped ?\n");
    else{
        printf("SHDR_TBL\tOFFSET \tVADDR \t\tSIZE \tTYPE\n");
        for (i = 0; i < ehdr.e_shnum; i++){
            fseek(f, ehdr.e_shoff + (i * ehdr.e_shentsize), SEEK_SET);
            fread(&shdr[i], ehdr.e_shentsize, 1, f);
            printf("\t0x%lx \t0x%06lx \t0x%lx \t%s\n", shdr[i].sh_offset, shdr[i].sh_addr, shdr[i].sh_size, sh_type_tostr(shdr[i].sh_type));
        }
        printf("\n");
    }

    return shdr;
}


/* Read the dynamic segment from f 
 * @phdr is the program header table
 * @count is the size of the table
 * @f is the (opened) file descriptor
 * */
ElfW(Dyn) *get_dyn(ElfW(Phdr) *phdr, int count, FILE *f)
{
    int i;
    size_t dyn_count;
    ElfW(Dyn) *dynamic;

    if (!phdr || count == 0)
        return NULL;

    for (i = 0; i <count ; i++)
    {
        if (phdr[i].p_type == PT_DYNAMIC)
        {
            if (phdr[i].p_filesz == 0)
            {
                printf("#The dynamic section is empty (?). I cannot process it.\n");
                continue;
            }

            // Load the dynamic section into dynamic[].
            dynamic = malloc(phdr[i].p_filesz);
            if (!dynamic)
                return NULL;

            fseek(f, phdr[i].p_offset, SEEK_SET);
            fread(dynamic, phdr[i].p_filesz, 1, f);
            dyn_count = phdr[i].p_filesz / sizeof(ElfW(Dyn));
            printf("--- Found a dynamic segment @ %#lx with %lu entries ---\n",
                    phdr[i].p_offset, dyn_count);
        }
    }

    return dynamic;
}


}
/* Print the dynamic section*/
void print_dynamic(ElfW(Dyn) *dynamic)
{
    int i;
    char *str;

    if(!dynamic){
        printf("\tDynamic is NULL\n");
        return;
    }

    printf("\tINDEX \t TYPE \t\tVADDR \tVALUE \t\tSEGMENT \t\tTYPE(STRING)\n");
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
    {
        if (addr_belongs_to_segment(dynamic[i].d_un.d_ptr, text_seg))
            str = ".text";
        else if (addr_belongs_to_segment(dynamic[i].d_un.d_ptr, data_seg))
            str = ".data";
        else
            str = "none";

        printf("\tidx %d \t (%#06lx) \t @%#06lx \t0x%06lx \t%s+%d \t" , i,
                dynamic[i].d_tag, dynamic[i].d_un.d_ptr, dynamic[i].d_un.d_val,
                str, segment_offset(dynamic[i].d_un.d_ptr) );
        printf("\t(%s)\n", d_tag_tostr(dynamic[i].d_tag));

    }
    printf("\n");
}


/* Allocate a segment into memory */
struct segment *load_sgmt(ElfW(Phdr) *seg_hdr, FILE *f)
{
    char *image;
    int size, i;
    struct segment *segment;

    if (seg_hdr->p_memsz < seg_hdr->p_filesz){
        printf("ERROR: p_memsz < p_filesz. This is incorrect. Loading aborted"
                "for segment @%#lx.\n", seg_hdr->p_offset);
        return NULL;
    }

    image = malloc(seg_hdr->p_memsz);
    if (!image)
        return NULL;

    fseek(f, seg_hdr->p_offset, SEEK_SET);

    /* Read p_filesz bytes from file */
    fread(image, seg_hdr->p_filesz, 1, f);

    /* Extra bytes in memory are 0s (BSS)*/
    size = seg_hdr->p_memsz - seg_hdr->p_filesz;
    if (size > 0)
    {
        for (i=0; i<size; i++)
            image[seg_hdr->p_filesz + i] = 0x0;
    }

    segment = malloc(sizeof(struct segment));
    segment->img = image;
    segment->memsz = seg_hdr->p_memsz;
    segment->vaddr = seg_hdr->p_vaddr;

    return segment;
}


char *needed_objects(char *string_table, ElfW(Dyn) *dynamic)
{
    int i;
    char *str;
    int offset;

    printf("--- Needed objects (dependencies) ---\n");
    for (i=0; dynamic[i].d_tag != DT_NULL; i++)
    {
        if (dynamic[i].d_tag == DT_NEEDED)
        {
            offset = dynamic[i].d_un.d_ptr;
            str = &string_table[offset];
            printf("\tDT_NEEDED: %s (@offset %d in string table.)\n", str, offset);
        }
    }
    printf("\n");

    return NULL;
}



/* Hack (let's call it heuristic)
 * As we don't have section headers, it is hard to guess the size of the symbol
 * table (DT_SYMENT does not give the size of the table, but the size of single
 * elements instead. 
 * Thus, we make the assumption that the entries are correct until we meet a
 * name that is outside of the string table, which should not happen.
size_t guess_symtab_sz(ElfW(Dyn) *dynamic)
{
    int i=0;
    size_t strsz;
    ElfW(Sym) *symtab;

    symtab = get_symtab_ptr(dynamic);
    strsz = _get_strtab_sz(dynamic);
    for (i=1; symtab[i].st_name < strsz; i++)
        continue;
    printf("Guessed %#x\n", i);
    return i;
}
 * */


/* For each entry of the symbols table, fetch the corresponding name from
 * string table)*/
void print_symbols(ElfW(Dyn) *dynamic)
{
    size_t symsz;//, strsz;
    char *strtab, *type, *info;
    ElfW(Sym) *symtab;
    int i;
    int pos;

    /*
    if ((symsz = guess_symtab_sz(dynamic)) == 0)
        return;
        */

    if (!(symtab = get_symtab_ptr(dynamic)) || !(strtab =
                get_strtab_raddr(dynamic)))
        return;

    printf("--- Symbol table ---\n");
    printf("\tIDX \tTYPE \t\tBINDING \tADDR \t\tNAME\n");

    /* We assume that there are no section headers (this way, we can deal with
     * stripped binaries, so we don't have information about the size of the
     * symbols table. As names are indexes in the string table, we can safely
     * assume that we should stop when we meet the first index that is outside
     * of the string table, this way we get the right size.*/
    for (i=1; i < symsz; i++)
    {
        /* The first symbol is always STN_UNDEF so we skip it*/
        if (symtab[i].st_name == STN_UNDEF)
            continue;

        pos = (int) symtab[i].st_name;
        type = sh_index_tostr(symtab[i].st_shndx);
        info = symb_info_tostr(symtab[i].st_info);
        printf("\t%#x \t%s \t%s \t\t%#06lx \t%s\n", i, type, info,
                symtab[i].st_value, &strtab[pos]);
    }

    printf("\t---\n\tSymtab size is %#x @vaddr %p\n\n", i, symtab);
}



void print_rela(ElfW(Dyn) *dynamic)
{
    int i=0, sidx;
    ElfW(Rela) *rela;
    ElfW(Word) relasz;
    size_t sz;
    //ElfW(Sym) symtab;

    rela = get_rela_ptr(dynamic);
    //sz = guess_symtab_sz(dynamic);
    relasz = get_dyn_val(dynamic, DT_RELASZ);
    printf("Relasz has size %#x\n", relasz);
    /*
    relasz = get_rela_sz(dynamic);
    strsz = get_strtab_sz(dynamic);
    */
    //symtab = get_symtab_ptr(dynamic);

    printf("--- Relocations (DT_RELA)---\n\tVADDR \tSYMTAB_INDEX\n");
    for(i=0; i<sz; i++){
        sidx = ELF_R_SYM(rela[i].r_info); // symtab index
        printf("\t%#lx\t%#x\n\n", rela[i].r_offset, sidx);
    }
}

void print_rel(ElfW(Dyn) *dynamic)
{
    ElfW(Rel) *rel;
    ElfW(Word) val;
    int i, sidx;
    size_t sz;

    rel = (ElfW(Rel)*) get_dyn_real_addr(dynamic, DT_PLTREL);
    val = get_dyn_val(dynamic, DT_PLTRELSZ);

    if(!rel)
        return;
    if (sz <= 0)
        return;

    printf("--> DT_PLTRELSZ is 0x%x\n", val);

    printf("--- Relocations (DT_PLTREL)---\n\tVADDR \tSYMTAB_INDEX\n");
    for (i=0; i<sz; i++)
    {
        sidx = ELF_R_SYM(rel[i].r_info);
        printf("\t%#lx\t%#x\n\n", rel[i].r_offset, sidx);
    }
}

/* Load a binary file into memory
 * @ehdr is a copy of the elf header
 * @phdr is a pointer to the program header
 * @f is a pointer the (opened) binary file to load
 * */
int load(ElfW(Ehdr) ehdr, ElfW(Phdr) *phdr, FILE *f){
    ElfW(Dyn) *dynamic; // Dynamic segment
    int text_idx, data_idx, i;
    size_t symsz;
    text_idx = find_text_index(ehdr, phdr);
    data_idx = find_data_index(ehdr, phdr);
    char *strtab, *str;

    if (text_idx == -1 || data_idx == -1){
        printf("ERROR, bad segment index in program header table\n");
        return -ENODATA;
    }


    data_seg = load_sgmt(&phdr[data_idx], f);
    text_seg = load_sgmt(&phdr[text_idx], f);

    printf("--- Segment loading---\n");
    for(i=0; i<ehdr.e_phnum; i++)
    {
        if(i == data_idx || i == text_idx)
            continue;

        if(addr_belongs_to_segment(phdr[i].p_vaddr, data_seg))
            printf("\t->segment %d @vaddr %#lx belongs to .data\n", i, phdr[i].p_vaddr);

        else if(addr_belongs_to_segment(phdr[i].p_vaddr, text_seg))
            printf("\t->segment %d @vaddr %#lx belongs to .text\n", i, phdr[i].p_vaddr);
    }
    printf("\n");


    dynamic = get_dyn(phdr, ehdr.e_phnum, f);
    print_dynamic(dynamic);

    strtab = get_strtab_raddr(dynamic);
    str = needed_objects(strtab, dynamic);

    print_symbols(dynamic);
    print_rela(dynamic);
    print_rel(dynamic);

    free(dynamic);
    free(data_seg->img);
    free(text_seg->img);
    free(data_seg);
    free(text_seg);

    return 0;
}


/* Display basic info contained in the ELF header*/
void print_basic_info(ElfW(Ehdr ehdr))
{
    printf("Entry point: %#lx\n", ehdr.e_entry);
    printf("Machine_type: %s", _get_arch(ehdr));
}


int main(int argc, char *argv[])
{
    ElfW(Ehdr) ehdr; // ELF header
    ElfW(Phdr) *phdr; // Program header table
    ElfW(Shdr) *shdr; // Section header
    FILE *f;
    const char *binfile;
    char *filename;

    if (argc < 2)
    {
        printf("No filename given\n");
        exit(EXIT_FAILURE);
    }

    binfile = argv[1];

    f = fopen(binfile,"r");
    if (!f)
    {
        printf("Could not open file\n");
        exit(EXIT_FAILURE);
    }

    /* Determine the architecture type*/
    if ((get_elf_class(f) != ELFCLASS64) && (get_elf_class(f) != ELFCLASS32))
    {
        printf("Invalid ELF file\n");
        exit(EXIT_FAILURE);
    }

    /* Get ELF header*/
    rewind(f);
    fread(&ehdr, sizeof(Elf64_Ehdr), 1, f);
    print_basic_info(ehdr);

    /* Get program header table*/
    phdr = get_phdr(ehdr, f);
    print_phdr(phdr, ehdr.e_phnum);

    /* Get section headers */
    shdr = get_shdr(ehdr, f);

    /* Load segments */
    load(ehdr, phdr, f);

    fclose(f);

    free(phdr);
    free(shdr);
    

    return 0;

}
