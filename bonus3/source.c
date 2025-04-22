#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char buffer[160];

    FILE *fd = fopen("/home/user/end/.pass", "r");
    memset(buffer, 0, sizeof(buffer));
    if (fd == 0 || argc != 2) {
        return -1;
    }
    fread(buffer, 66, 1, fd);
    buffer[59] = 0;
    *(buffer + atoi(argv[1])) = 0;
    fread(&buffer[66], 1, 65, fd);
    fclose(fd);
    if (strcmp(buffer, argv[1]) == 0) {
        execl("/bin/sh", "sh", NULL);
    }
    else {
        puts(&buffer[66]);
    }
    return 0;
}
