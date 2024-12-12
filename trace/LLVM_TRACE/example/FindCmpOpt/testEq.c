#include <stdio.h>

int vuln(){
    float a = 1.0f;
    float b = 1.0f;

    if (a == b) {
        printf("a is equal to b\n");
    } else {
        printf("a is not equal to b\n");
    }
    if(b == 2.0f)
        return 0;

    return 1;
}


int main() {
    float a = 1.0f;
    float b = 1.0f;

    if (a == b) {
        printf("a is equal to b\n");
    } else {
        printf("a is not equal to b\n");
    }

    return 0;
}
