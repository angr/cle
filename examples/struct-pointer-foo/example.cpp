struct Foo {
  Foo *f;
};

int foo(Foo f) { return 0; }
Foo bar(Foo *f) { return *f; }
