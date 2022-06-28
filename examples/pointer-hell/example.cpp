struct Foo {
  int x;
};
struct Bar {
  Foo f;
};
struct Baz {
  Foo *f;
};
struct Bax {
  Bar *b;
};
struct Bux {
  Baz *b;
};

void foo(Foo f){}
void bar(Bar b){}
void bar(Bar *b){}
void baz(Baz b){}
void baz(Baz *b){}
void bax(Bax b){}
void bax(Bax *b){}
void bux(Bux b){}
void bux(Bux *b){}
