#include <stdio.h>

int main(int argc, char *argv[])
{
    p();
    return 0;
}

char *p()
{
    char *str;
    char *buffer;

    fflush(stdout);
    gets(buffer);
    if (((int)buffer & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", buffer);
        exit(1);
    }
    puts(buffer);
    str = strdup(buffer);
    return str;
}
