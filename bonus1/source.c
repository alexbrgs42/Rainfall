#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
  char dest[40];
  int nb;

  nb = atoi(argv[1]);
  if (nb > 9)
    return 1;
  memcpy(dest, argv[2], 4 * nb);
  if (nb == 1464814662)
    execl("/bin/sh", "sh", NULL);
  return 0;
}