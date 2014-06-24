#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_LIBS 20


/* The following makes use of the LD's audit interface to resolve symbols and
 * get addresses where it loads shared libraries at runtime.
 *
 * Compile this code as a position independent shared library (gcc -fpic
 * --shared) and run the target program using LD_AUDIT=./this_lib
 *  /path/to/program.
 */


const char *library="LIB";
const char *symbol="SYM";
const char *logfile = "./ld_audit.out";

/* Simple strucutre to hold information about loaded objects*/
struct mapped
{
    uintptr_t *cookie;
    struct link_map *map;
};

/* This is a global list of mapped objects */
struct mapped *maps; //[MAX_LIBS];

/* Perform a lookup in the list*/
struct mapped *maps_lookup(uintptr_t *cookie)
{
    int i;
    for(i = 0; i<MAX_LIBS; i++)
    {
        if (!cookie || !maps[i].cookie)
            break;

        if (*(maps[i].cookie) == *cookie)
            return &maps[i];
    }
    return NULL;
}

/* Add a mapped object to the list*/
int map_add(struct link_map *map, uintptr_t cookie){
    int i;
    if (! maps_lookup(&cookie))
        for (i=0; i<MAX_LIBS; i++)
        {
            if (maps[i].cookie == NULL)
            {
                maps[i].cookie = &cookie;
                maps[i].map = map;
                break;
            }
        }
}

// Append info to the log file
void log_append(const char*type, const char *name, ElfW(Addr) addr)
{
FILE *path;

path = fopen(logfile, "a");
fprintf(path, "%s,%s,%p\n", type, name, addr);
fclose(path);
}

// Required by LD's audit interface
unsigned int la_version(unsigned int version)
{
    int i;
    log_append("\n---", "audit initialized (new trace)", 0x0);

    maps = malloc(sizeof(struct mapped) * MAX_LIBS);
    if (!maps)
        printf("Could not allocate memory :(\n");
    else
    { // Initialize list of mapped libs to NULL
        for (i=0; i<MAX_LIBS; i++)
            maps[i].cookie = NULL;
    }

    return version;
}

// Loaded libraries and their addresses
unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
    ElfW(Dyn) *dyn;
    struct r_debug *r_debug;

    if (map->l_addr)
        log_append(library, map->l_name, map->l_addr);

     //dyn = map->*l_ld;
     for (dyn = _DYNAMIC; dyn->d_tag != DT_NULL; ++dyn)
         if (dyn->d_tag == DT_DEBUG)
             r_debug = (struct r_debug *) dyn->d_un.d_ptr;

    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}


// Symbols addresses
uintptr_t la_symbind32(Elf32_Sym *sym, unsigned int ndx, uintptr_t *refcook,
        uintptr_t *defcook, unsigned int *flags, const char *symname)
{
    log_append(symbol, symname, sym->st_value);
    return sym->st_value;
}
uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
        uintptr_t *defcook, unsigned int *flags, const char *symname)
{
    log_append(symbol, symname, sym->st_value);
    return sym->st_value;
}


/* This function is called after all shared libraries have been loaded, and
 control is about to be transfered to the program. In case the loader was
 invoked with LD_BIND_NOW, we know that at this point, all relocations have
 been performed already by LD. */

void la_preinit(uintptr_t *cookie){

    log_append("---", "transfered control to the program", 0x0);
    free(maps);
}


