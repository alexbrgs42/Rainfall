#include <string.h>
#include <unistd.h>
#include <stdio.h>

void p(char *dest, char *sep) {
  char buffer[4120];

  puts(sep);
  read(0, buffer, 4096);
  *strchr(buffer, '\n') = 0;
  strncpy(dest, buffer, 20);
}

void pp(char *dest) {
  char src1[20];
  char src2[20];

  p(src1, " - ");
  p(src2, " - ");
  strcpy(dest, src1);
  dest[strlen(dest)] = ' ';
  strcat(dest, src2);
}

int main(void) {
  char str[42];

  pp(str);
  puts(str);
  return 0;
}
