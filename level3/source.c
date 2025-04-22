#include <stdlib.h>
#include <stdio.h>

void v() {
    char buffer[536];

    fgets(buffer, 512, stdin);
    printf(buffer);
    if (*((int *)0x0804988c) == 64) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
    return ;
}

int main() {
    v();
    return 0;
}
