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

## TODO:

 - if we decide to use this, create automated tests akin to compspec
 - can we implement different parsing for registers based on type?
