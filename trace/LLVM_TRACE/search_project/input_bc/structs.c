#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct tmp_a{
    size_t c;
    size_t b;
};

struct tmp_x_a{
    size_t *c;
    size_t b;
};

struct tmp_x_b{
    char *buf;
    size_t size;
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

void fun_b(){
    struct tmp_x_a * ptr_a;
    ptr_a = malloc(sizeof(struct tmp_x_a));
    ptr_a->b = 114514;
    free(ptr_a);

}

void fun_c(size_t *a, int b, struct tmp_x_b *c){
    struct tmp_x_a tmp_a;
    tmp_a.c = a;
    tmp_a.b = b;
    struct tmp_x_b tmp_b;
    memcpy(&tmp_b, c, sizeof(struct tmp_x_b));
}

void fun_d(struct tmp_x_b *c, char *buf){
    memcpy(c->buf, buf, sizeof(*buf));
}

int main(void){
    struct tmp_a v1;
    struct tmp_x_a v2;
    v2.b = 99;
    struct tmp_b v3;
    struct tmp_c v4;
    struct tmp_x_b v5;
    v5.buf = "pwh";
    size_t v6 = 999;
    fun_c(&v6, 323, &v5);

}






