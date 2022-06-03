#include <stdint.h>

extern void bigcall(long a, long b, long c, long d, long e, __int128_t f);

int main(int argc, char *argv[])
{
   __int128_t c;
   c = 0x0000000000000006;
   c = c << 64;
   c += 0x0000000000000007;
   bigcall(1, 2, 3, 4, 5, c);
   return 0;
}
