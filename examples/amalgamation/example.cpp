// internal linkage variable (won't be included)
static int inty = 2;

// external linkage and global scope - will be included
bool booley = true;
long double doubley = 1.0;

//extern int intyterny;

void foo() {
//  intyterny = 1;
}

int main(int argc, char * argv[]) {
    return 0;
}

struct Structy {
   int one;
   double two;
   char * three;
};

int fooreturn(int one, Structy * two) {
    return one;
}

