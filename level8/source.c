#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *service;
char *auth;

int main(int argc, char **argv)
{
    char buffer[160];

    while (1)
    {
        printf("%p, %p \n", auth, service);
        if (!fgets(buffer, 128, stdin))
            break;
        if (!memcmp(buffer, "auth ", 5))
        {
            auth = malloc(4);
            auth = 0;
            if (strlen(buffer + 5) <= 30) {
                strcpy(auth, buffer + 5);
            }
        }
        if (!memcmp(buffer, "reset", 5))
            free(auth);
        if (!memcmp(buffer, "service", 6))
            service = strdup(buffer + 7);
        if (!memcmp(buffer, "login", 5))
        {
            if (*(auth + 32))
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }
    return 0;
}
