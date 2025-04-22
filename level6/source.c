#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void m() {
    puts("Nope");
    return ;
}

void n() {
    system("/bin/cat /home/user/level7/.pass");
    return ;
}

int main(int argc, char **argv) {
    char *buffer_a = malloc(64);
    char *buffer_b = malloc(4);
    buffer_b = (char *)0x08048468;  // address of m()
    strcpy(buffer_a, argv[1]);
    buffer_b; // call its address
    return 0;
}
