int foo(int x) { return x + 1; }

__attribute__((always_inline))
static double bar(double d) { return d + foo(d); };

int start(double d) {
    double dd = bar(d);
    return dd + 1;
}
