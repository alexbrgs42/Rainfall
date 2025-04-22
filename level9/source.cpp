#include <stdlib.h>
#include <string.h>

class N {
    public:
        int value;
        char str[108];

        N(int);
        int operator+(N&);
        int operator-(N&);
        int setAnnotation(char *);
};

N::N(int val)
{
  this->value = val;
}

int N::operator+(N& that) {
    this->value += that.value;
    return this->value;
}

int N::operator-(N& that) {
    this->value -= that.value;
    return this->value;
}

int N::setAnnotation(char *str) {
    int len = strlen(str);
    memcpy(this->str, str, len);
    return len;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        exit(1);
    }
    N *a = new N(5);
    N *b = new N(6);
    a->setAnnotation(argv[1]);
    a->str;  // calling new buffer
    return a->operator+(*b);
}