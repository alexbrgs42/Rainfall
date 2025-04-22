#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int language;

void greetuser(char *name) {
    char hello_msg[88];

    memset(hello_msg, 0, sizeof(hello_msg));
    if (language == 1) {
        strcpy(hello_msg, "Hyvää päivää ");
    }
    else if (language == 2) {
        strcpy(hello_msg, "Goedemiddag! ");
    }
    else if (language == 0) {
        strcpy(hello_msg, "Hello ");
    }
    strcat(hello_msg, name);
    puts(hello_msg);
}

int main(int argc, char **argv) {
    char dest[160];

    if (argc == 3) {
        memset(dest, 0, sizeof(dest));
        strncpy(dest, argv[1], 40);
        strncpy(&dest[40], argv[2], 32);
        char *lang = getenv("LANG");
        if (lang != 0) {
            if (memcmp(lang, "fi", 2) == 0) {
                language = 1;
            }
            else if (memcmp(lang, "nl", 2) == 0) {
                language = 2;
            }
        }
        greetuser(dest);
    }
    return 0;
}