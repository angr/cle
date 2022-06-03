int foo(int x) { return x + 1; }
double bar(double d) { return d + foo(d); };

inline int cube(int s){
    return s*s*s;
}

int start(double d) {
    double dd = bar(d);
    return dd + 1;
}
