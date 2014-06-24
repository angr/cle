#include <stdlib.h>
#include <bfd.h>
#include <elf.h>
#include <stdio.h>


const char *get_bfd_arch(const char* filename)
{
    bfd *bfd;
    bfd_boolean r;

    if (!filename)
        return NULL;

    bfd_init();
    bfd = bfd_openr(filename, NULL);

    if (!bfd)
    {
        printf("Error, NULL bfd\n");
        return NULL;
    }

    r = bfd_check_format(bfd, bfd_object);

    if (!r) {
        printf("WFT??\n");
        return NULL;
    }

    //arch_size = bfd_get_arch_size (bfd);

    return bfd_printable_name(bfd);
}

