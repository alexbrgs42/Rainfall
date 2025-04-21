#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    if (atoi(argv[1]) == 423) {
        char *str[32];
        str[0] = strdup("/bin/sh");
        str[1] = NULL;
        uid_t egid = getegid();
        uid_t euid = geteuid();
        setresgid(egid, egid, egid);
        setresuid(euid, euid, euid);
        execv("/bin/sh", str);
    }
    else {
        fwrite("No !\n", 1, 5, stderr);
    }
    return 0;
}