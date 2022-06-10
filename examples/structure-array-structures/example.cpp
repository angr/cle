
struct StructyChild {
   int one;
};

struct Structy {
   StructyChild * child[5];
};

int foo(int one, Structy * arrayOfStructures[10]) {
    return one;
}

int main(int argc, char * argv[]) {
    return 0;
}

