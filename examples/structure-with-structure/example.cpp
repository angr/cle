
struct StructyNested {};

struct StructyChild {
   int one;
   double two;
   char * three;
   StructyNested * useless;
};

struct StructyParent {
   StructyChild * child;
   bool wonka;
};

int foo(int one, StructyChild * two, StructyParent * three) {
    return one;
}

int main(int argc, char * argv[]) {
    return 0;
}

