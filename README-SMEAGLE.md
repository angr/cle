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

It's fairly reasonable to use dwarf locations (the angr developers think so too)
but if you want to force using manually encoded ABI rules:

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

## TODO:
 - Vanessasaurus:
   - Examples to add:
     - enum as a parameter
     - fixed size arrays
     - structures of structures
     - structures of arrays of structures
     - structures of arrays of arrays
     - complex types (look at unit tests)
     - const versions of types (also in until tests)
     - just review smeagle unit tests
   - option to filter out some line programs based on location (to deal with unknown pointers) 
 - Tim:
   - Write out high level approach
   - need to complement this with C++ interface to get callsites into Python. Only need for callsites for now, unless speed is an issue in the future.
 - void pointers don't seem to show up in dwarf with global variables, without they do.
 - function as parameter doesn't have name, variable info, nothing, empty subroutine. We think there is missing dwarf information.
 - need to look again at 8 byte analysis (not entirely right)
 - eventually will want wrapper that uses cle to do Matt's special location parsing - "offsets"
 - bit fields - not a priority because uncommon
 - exceptions also need to wait
 - Take a look at exceptions example - in lsda.py I commnted out else case that is triggered
