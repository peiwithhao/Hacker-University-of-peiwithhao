#include <stdio.h>
#include <string.h>

size_t global_a = 0;
size_t global_b = 0;
size_t global_c = 0;
size_t global_d = 0;
size_t global_e = 0;

struct st_a {
    size_t a;
    size_t * b;
    char c[0x10];
};


struct st_b {
    ssize_t *a;
    size_t * b;
    char c[0x20];
};

struct st_a global_st_a = {
    .a = 14,
    .c = "peiwithhao",
};

int vuln_a(){
    int a = 0;
    struct st_b sb = {};
    return a;
}

int vuln_b(int a, int b){
    a = 1;
    struct st_a sa = {};
    sa.a = 14;
    memcpy(sa.c, "peiwithhao", 10);
    b = 2;
    return a+b;
}

int vuln_c(int a, int b, int c){
    a = 1;
    b = 2;
    c = 3;
    return a+b+c;
}
