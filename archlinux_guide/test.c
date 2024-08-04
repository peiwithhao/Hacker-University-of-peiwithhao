#include <stdio.h>
#include <string.h>
struct file_info{
    int file_sz;
    char a[];
};
int main(void){
    struct file_info fi;
    char b[0x10];
    memset(fi.a, 'a', 0x10); 
  printf("size:%d\n", sizeof(fi));
}
