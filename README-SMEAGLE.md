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
$ python dev.py examples/libtest.foo
```

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

You'll need to add pytest and deepdiff to your environment:

```bash
$ pip install pytest deepdiff
```
And then you can run tests:

```bash
$ pytest tests.py
```

## TODO:

 - can we implement different parsing for registers based on type?
 - Take a look at exceptions example - in lsda.py I commnted out else case that is triggered
