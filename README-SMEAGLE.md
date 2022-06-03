# Smeagle Facts

This is a variant of cle modified to generate json corpora. You can use the [dev.py](dev.py)
script to run any particular example.

```bash
$ python -m venv env
$ source env/bin/activate
$ pip install -e .
```

Then run targeting an example directory in [examples](examples)

```bash
$ python dev.py examples/bigcall/test.so
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

 - can we implement different parsing for registers based on type?
 - Take a look at exceptions example - in lsda.py I commnted out else case that is triggered
