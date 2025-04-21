#include <stdio.h>
#include <stdlib.h>

void run() {
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
    return ;
}

int main() {
    char buffer[76];
    gets(buffer);
    return ;
}
