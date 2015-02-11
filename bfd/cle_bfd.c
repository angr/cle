#include <stdlib.h>
#include <bfd.h>
#include <elf.h>
#include <stdio.h>
#include <errno.h>

/* These are a bunch of simple Ctypes friendly functions using the BFD library
 * to recover information that is needed by Clé */


static inline const bfd_arch_info_type *get_bfd_info(const char *filename);
static bfd *open_bfd(const char* filename);

/* This gives the name of the architecture, e.g.: mips*/
const char *get_bfd_arch_name(const char* filename)
{

    const bfd_arch_info_type *info;

    info = get_bfd_info(filename);
    if (!info)
        return NULL;
    return info->arch_name;
}

int get_bfd_file_flags(const char* filename)
{
    bfd *bfd;

    bfd = open_bfd(filename);
    if (!bfd)
        return -EINVAL;


    return bfd_get_file_flags(bfd);
}

/* This gives the printable name of the architecture, e.g.: mips:3000*/
const char *get_bfd_arch_pname(const char* filename)
{
    bfd *bfd;

    bfd = open_bfd(filename);
    if (!bfd)
        return "ERROR";


    return bfd_printable_name(bfd);
}


/* How many bits per address on this architecture ? */
int get_bits_per_addr(const char *filename)
{

    const bfd_arch_info_type *info;

    info = get_bfd_info(filename);
    if (!info)
        return 0;
    return info->bits_per_address;
}


int get_arch_size(const char *filename)
{
    int arch_size;

    bfd *bfd;
    bfd = open_bfd(filename);
    if (!bfd)
        return 0;

    arch_size = bfd_get_arch_size (bfd);

    return arch_size;
}

const char* get_arch_byte_order(const char *filename)
{
    bfd *bfd;
    bfd = open_bfd(filename);
    if (!bfd)
        return 0;

    if bfd_little_endian(bfd)
        return "LSB";
    else if bfd_big_endian(bfd)
        return "MSB";
    else
        return "ERR";
}



/* ##### The following static functions are not meant to be called from Python
 * ####*/

static bfd *open_bfd(const char* filename)
{
    bfd *bfd;
    bfd_boolean r;

    if (!filename)
        return NULL;

    bfd_init();
    bfd = bfd_openr(filename, NULL);

    r = bfd_check_format(bfd, bfd_object);
    if (!r)
        return NULL;

    return bfd;
}




/* Stub to recover the bfd_arch_info_type structure */
static inline const bfd_arch_info_type *get_bfd_info(const char *filename)
{
    const char *archname;
    const bfd_arch_info_type *info;

    if (!filename)
        return NULL;

    archname = get_bfd_arch_pname(filename);
    info = bfd_scan_arch(archname);
    return info;
}


