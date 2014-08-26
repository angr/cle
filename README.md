Clé loads binaries and their associated libraries, resolves imports and
provides an abstraction of process memory the same way as if it was loader by
the OS's loader (without ASLR).

CLE's loader is implemented in the Ld class. 
There are two backends to CLE:

    - Elf, as its name says, loads ELF binaries.  With Elf, the addresses are
      the same as if you run the binary into qemu-{arch} (e.g., qemu-x86_64) as
      provided by the qemu-user package.

    - IdaBin relies on IDA (through IdaLink) to get information from the
      binaries. As of now, the addresses are not the same as if loader on a
      real system (see "known bugs and limitations" below). 

The backend to use is specified by the force_ida switch in Ld's constructor.
    force_ida = True: IdaBin
    force_ida = False: Elf

# Usage example

ld = cle.Ld("path/to/binary", force_ida=bool, load_libs=bool,
skip_libs=[list, of, libs])

    force_ida: use IDA as a backend (through the IdaBin class)
    load_libs: load shared libraries the binary depends on
    skip_libs: a list containing names of libraries to exclude from loading

# Binaries' location

    - When using IDA as a backend, copies of all the binaries (the main binary
      and shared objects) are placed into a temporary folder:
      /tmp/cle_binary-name_architecture (e.g., /tmp/cle_ls_mips) so that it
      doesn't interfere with other IDA sessions on the same binaries (and also
      because IDA requires write permission to the same path to write its .db
      files).

    - When using CLE, the binaries are directly loaded from their original locations.

# Finding shared libraries

    - Ld determines which shared objects are needed when loading binaries, and
      searches for them in the following order:
        - in the temporary directory of the project if it exists from previous
          executions for the same binary AND architecture
        - in the same folder as the main binary
        - in the system (in the corresponding library path for the architecture
          of the binary, e.g., /usr/arm-linux-gnueabi/lib for ARM)

       If no binary is found with the correct architecture, Ld raises an
       exception, unless the library causing trouble is defined in skip_libs. 


# Dependencies

You will need binutils-multiarch-dev and gcc for mips, arm, ppc, x86 and
x86_64. On Debian, this is provided by emdebian.


# Manual install

To install Clé manually, you need to compile and install the code in the
subdirectories bfd, cle and ld_audit. The best way to do it is in a python
virtual
environment, e.g.:

    workon angr

And then:
    make 
    make install
in each directory.


# Auto install

Just git clone git@git.seclab.cs.ucsb.edu:angr/angr_setup.git and run the
install script.

# Known bugs and limitations (as of 08/26/14)

    - When using IdaBin, addresses do not match the addresses of an actual
      execution because of a bug IDA, causing it to crash when trying to
      rebase binaries at high addresses.

    - As of now, relocations on MIPS are wrong when using Elf. It also seems
      that, due to a bug in IDA resulting in wrong GOT entries when rebasing
      MIPS binaries, that these are wrong with IdaBin too.

    - Resolving imports after relocation may miss symbols when using IdaBin,
      most likely because IDA's exports list seems wrong on some architectures
      (idautils.Entries() does not contain all exports)
