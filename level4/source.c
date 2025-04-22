#include <stdlib.h>
#include <stdio.h>

void p(char *str) {
    printf(str);
    return ;
}

void n() {
    char buffer[536];

    fgets(buffer, 512, stdin);
    p(buffer);
    if (*((int *)0x8049810) == 16930116) {
        system("/bin/cat /home/user/level5/.pass");
    }
    return ;
}

int main() {
    n();
    return 0;
}
