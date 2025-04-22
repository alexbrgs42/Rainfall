#include <stdlib.h>
#include <stdio.h>

int o() {
    system("/bin/sh");
    exit(1);
}

int n() {
    char buffer[536];

    fgets(buffer, 512, stdin);
    printf(buffer);
    exit(1);
}

int main() {
    n();
    return 0;
}
