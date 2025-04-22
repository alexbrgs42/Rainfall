#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct data {
    int   num;
    char *buf;
};

char *c;

void m() {
    time_t t = time(0);
    printf("%s - %d\n", c, (int)t);
    return ;
}

int main(int argc, char **argv) {
    struct data *a = malloc(8);
    a->num = 1;
    a->buf = malloc(8);
    
    struct data *b = malloc(8);
    b->num = 2;
    b->buf = malloc(8);
    
    strcpy(a->buf, argv[1]);
    
    strcpy(b->buf, argv[2]);
    
    FILE *file = fopen("/home/user/level8/.pass", "r");
    
    fgets(c, 68, file);
    
    puts("~~");
}
