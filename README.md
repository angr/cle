CLE loads binaries and their associated libraries, resolves imports and
provides an abstraction of process memory the same way as if it was loader by
the OS's loader.

# Installation

`$ pip install cle`

# Usage example

```python
>>> import cle
>>> ld = cle.Loader("/bin/ls")
>>> hex(ld.main_object.entry)
'0x4048d0'
>>> ld.shared_objects
{'ld-linux-x86-64.so.2': <ELF Object ld-2.21.so, maps [0x5000000:0x522312f]>,
 'libacl.so.1': <ELF Object libacl.so.1.1.0, maps [0x2000000:0x220829f]>,
 'libattr.so.1': <ELF Object libattr.so.1.1.0, maps [0x4000000:0x4204177]>,
 'libc.so.6': <ELF Object libc-2.21.so, maps [0x3000000:0x33a1a0f]>,
 'libcap.so.2': <ELF Object libcap.so.2.24, maps [0x1000000:0x1203c37]>}
>>> ld.addr_belongs_to_object(0x5000000)
<ELF Object ld-2.21.so, maps [0x5000000:0x522312f]>
>>> libc_main_reloc = ld.main_object.imports['__libc_start_main']
>>> hex(libc_main_reloc.addr)       # Address of GOT entry for libc_start_main
'0x61c1c0'
>>> import pyvex
>>> some_text_data = ld.memory.load(ld.main_object.entry, 0x100)
>>> irsb = pyvex.lift(some_text_data, ld.main_object.entry, ld.main_object.arch)
>>> irsb.pp()
IRSB {
   t0:Ity_I32 t1:Ity_I32 t2:Ity_I32 t3:Ity_I64 t4:Ity_I64 t5:Ity_I64 t6:Ity_I32 t7:Ity_I64 t8:Ity_I32 t9:Ity_I64 t10:Ity_I64 t11:Ity_I64 t12:Ity_I64 t13:Ity_I64 t14:Ity_I64

   15 | ------ IMark(0x4048d0, 2, 0) ------
   16 | t5 = 32Uto64(0x00000000)
   17 | PUT(rbp) = t5
   18 | t7 = GET:I64(rbp)
   19 | t6 = 64to32(t7)
   20 | t2 = t6
   21 | t9 = GET:I64(rbp)
   22 | t8 = 64to32(t9)
   23 | t1 = t8
   24 | t0 = Xor32(t2,t1)
   25 | PUT(cc_op) = 0x0000000000000013
   26 | t10 = 32Uto64(t0)
   27 | PUT(cc_dep1) = t10
   28 | PUT(cc_dep2) = 0x0000000000000000
   29 | t11 = 32Uto64(t0)
   30 | PUT(rbp) = t11
   31 | PUT(rip) = 0x00000000004048d2
   32 | ------ IMark(0x4048d2, 3, 0) ------
   33 | t12 = GET:I64(rdx)
   34 | PUT(r9) = t12
   35 | PUT(rip) = 0x00000000004048d5
   36 | ------ IMark(0x4048d5, 1, 0) ------
   37 | t4 = GET:I64(rsp)
   38 | t3 = LDle:I64(t4)
   39 | t13 = Add64(t4,0x0000000000000008)
   40 | PUT(rsp) = t13
   41 | PUT(rsi) = t3
   42 | PUT(rip) = 0x00000000004048d6
   43 | t14 = GET:I64(rip)
   NEXT: PUT(rip) = t14; Ijk_Boring
}
```

# Valid options

For a full listing and description of the options that can be provided to the
loader and the methods it provides, please examine the docstrings in
`cle/loader.py`. If anything is unclear or poorly documented (there is much)
please complain through whatever channel you feel appropriate.

# Loading Backends

CLE's loader is implemented in the Loader class. 
There are several backends that can be used to load a single file:

    - ELF, as its name says, loads ELF binaries. ELF files loaded this way are
      statically parsed using PyElfTools.

    - PE is a backend to load Microsoft's Portable Executable format,
      effectively Windows binaries. It uses the (optional) `pefile` module.

    - Mach-O is a backend to load, you guessed it, Mach-O binaries. It is
      subject to several limitations, which you can read about in the
      [readme in the macho directory](backends/macho/README.md)

    - Blob is a backend to load unknown data. It requires that you specify
      the architecture it would be run on, in the form of a class from
      ArchInfo.

Which backend you use can be specified as an argument to Loader. If left
unspecified, the loader will pick a reasonable default.

# Finding shared libraries

- If the `auto_load_libs` option is set to False, the Loader will not
  automatically load libraries requested by loaded objects. Otherwise...
- The loader determines which shared objects are needed when loading
  binaries, and searches for them in the following order:
    - in the current working directory
    - in folders specified in the `ld_path` option
    - in the same folder as the main binary
    - in the system (in the corresponding library path for the architecture
      of the binary, e.g., /usr/arm-linux-gnueabi/lib for ARM, note that
      you need to install cross libraries for this, e.g.,
      libc6-powerpc-cross on Debian - needs emdebian repos)
    - in the system, but with mismatched version numbers from what is specified
      as a dependency, if the `ignore_import_version_numbers` option is True

- If no binary is found with the correct architecture, the loader raises an
  exception if `except_missing_libs` option is True. Otherwise it simply
  leaves the dependencies unresolved.
