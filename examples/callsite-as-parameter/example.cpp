#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
   close(getpid());
   return 0;
}
