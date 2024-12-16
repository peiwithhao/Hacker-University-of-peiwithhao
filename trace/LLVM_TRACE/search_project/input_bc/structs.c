#include <stdio.h>
struct tmp_a{
    size_t c;
    size_t b;
};

struct tmp_x_a{
    size_t *c;
    size_t b;
};


struct tmp_b{
    char a[0x10];
    size_t b;
};

struct tmp_c{
    long c;
    size_t b;

};

void fun_a(){
    struct tmp_a v1;
    struct tmp_x_a v2;
    v2.b = 11;
}



int main(void){
    struct tmp_a v1;
    struct tmp_x_a v2;
    v2.b = 99;
    struct tmp_b v3;
    struct tmp_c v4;
}






