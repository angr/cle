# Smeagle Facts

This is a variant of cle modified to generate json corpora. You can use the [dev.py](dev.py)
script to run any particular example. First, install dependencies:

```bash
$ python -m venv env
$ source env/bin/activate
$ pip install -e .
```

We need the latest of pyelftools:

```bash
$ git clone https://github.com/eliben/pyelftools /tmp/pyelftools
$ cd /tmp/pyelftools
$ pip install .
```

Then run targeting an example directory in [examples](examples)

```bash
$ python dev.py examples/bigcall/test.so
```

### Building

It's important to use a newer version of gcc, so I've been using a container to build:

```bash
$ docker run -it -v $PWD:/code -it gcc:12.1 bash -c "cd /code && make"
```
This also means you should use the container for dwarfdump

```bash
$ docker run -it -v $PWD:/code -it gcc:12.1 bash -c "apt-get update && apt-get install -y dwarfdump && dwarfdump /code/examples/bigcall/lib.so"
```

### Location Parsing

By default we use our custom location parsing. We will eventually have
this variable enabled to switch to it instead of using dwarf location lists.

```bash
$ export CLE_ELF_EXPERIMENTAL_PARSING=true
$ python dev.py examples/bigcall/test.so
```

This is currently supported only for x86_64/AMD64.

### Testing

The testing is setup so that you can add a new subdirectory to [examples](examples)
and it will be detected (built) when you do make:

```bash
$ make
```

And as noted above, you should use a conatiner compiler to be consistent:

```bash
$ docker run -it -v $PWD:/code -it gcc:12.1 bash -c "cd /code && make"
```

Each test folder must have the following:

 - the main program as example.cpp
 - any extra headers as example.h
 - A Makfile that builds to lib.so with debug symbols
 - any directories starting with an underscore will be skipped

You'll need to add pytest and deepdiff to your environment:

```bash
$ pip install pytest deepdiff
```
And then you can run tests:

```bash
$ pytest -xs tests.py 
============================================================================ test session starts ============================================================================
platform linux -- Python 3.9.12, pytest-7.1.2, pluggy-1.0.0
rootdir: /home/vanessa/Desktop/Code/cle
collected 7 items                                                                                                                                                           

tests.py /home/vanessa/Desktop/Code/cle/examples/callsite/lib.so
./home/vanessa/Desktop/Code/cle/examples/pointer-struct/lib.so
./home/vanessa/Desktop/Code/cle/examples/bigcall/lib.so
./home/vanessa/Desktop/Code/cle/examples/pointer/lib.so
./home/vanessa/Desktop/Code/cle/examples/math/lib.so
./home/vanessa/Desktop/Code/cle/examples/array/lib.so
./home/vanessa/Desktop/Code/cle/examples/inline/lib.so
.
```

The other kind of testing is just making sure you can run the json generation over some spack install.
I will usually start with a fresh clone of spack and then bind that same container to it:

```
git clone --depth 1 https://github.com/spack/spack /tmp/spack
cd /tmp/spack
docker run -it -v $PWD:/tmp/spack bash
/tmp/spack/bin/spack install ...
```

Then you can use [test.py](test.py) and adjust the root variable to the root
of your bound spack install. When you are done you'll either need to change
all the permissions of the opt install directory, uninstall from within the container,
or just uninstall with sudo outside it.

## Dwarf Monsters

These are cases with gcc 12.1 dwarf and the library here that I can't resolve. I'm noting here because Ben might be able to help or send them to the DWARF developers to look at.

 - /tmp/spack/opt/spack/linux-debian11-skylake/gcc-12.1.0/berkeley-db-18.1.40-vfunoaarenct4iydt4vzg3nycoqhavty/lib/libdb_stl.so: subprogram qsort has a formal parameter with only one attribute, a DW_AT_type that points to a DW_TAG_namespace (__debug) with nothing else. We parse this type as unknown.
 - /tmp/spack/opt/spack/linux-debian11-skylake/gcc-12.1.0/libbsd-0.11.5-ayxy3zjyufi6neh4fl5pie6n6rdc3jyn/lib/libbsd.so says it isn't elf, and someone suggested there is some kind of wrapper around it? I'm adding it to skip for now.
 - /tmp/spack/opt/spack/linux-debian11-skylake/gcc-12.1.0/hdf5-1.12.2-pakhqhweeyy5nkuprbtjnfq4oyv7yzjs/lib/libhdf5.so has a formal parameter with type label. It has a DW_AT_abstract_origin that links to another label with name "done."
  
## TODO:

 - Vanessasaurus:
 - Tim:
   - Write out high level approach
   - need to complement this with C++ interface to get callsites into Python. Only need for callsites for now, unless speed is an issue in the future.
 - DW_TAG_subrange_type in libpetsc.so has a dwarf expression and not number, right now we pass
 - How to handle `DW_TAG_GNU_formal_parameter_pack`? Right now we return the first child (but this is wrong) see dyninst libpcontrol.so
 - we need to add / parse [fortran types](https://docs.oracle.com/cd/E19957-01/805-4939/6j4m0vn6m/index.html) right now just Unknown
 - return type allocator does not correctly handle struct/union
 - void pointers don't seem to show up in dwarf with global variables, without they do.
 - `__ARRAY_SIZE_TYPE__` and `sizetype` in types.py
 - look at hpctoolkit libs to find example that suggests loading with blob - some kind of wrapped dwarf?
 - function as parameter doesn't have name, variable info, nothing, empty subroutine. We think there is missing dwarf information.
 - need to look again at 8 byte analysis (not entirely right)
 - eventually will want wrapper that uses cle to do Matt's special location parsing - "offsets"
 - bit fields - not a priority because uncommon
 - exceptions also need to wait
 - Take a look at exceptions example - in lsda.py I commnted out else case that is triggered
