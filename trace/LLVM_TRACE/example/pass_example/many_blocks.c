#include <stdio.h>
#include <sys/random.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

void filter_3(int num){
    int cmd = num % 3;
    switch(cmd){
    case 0:
        printf("you are a little hog\n");
        break;
    case 1:
        printf("you are a middle hog\n");
        break;
    case 2:
        printf("you are a big hog\n");
        break;
    default:
        break;
    }
}

void filter_2(int num){
    int cmd = num % 7;
    switch(cmd){
    case 0:
        printf("you are a little coke\n");
        break;
    case 1:
        printf("you are a big coke\n");
        break;
    default:
        break;
    }
}
int main(void){
    int fd = open("/dev/random", O_RDONLY);
    char num_str[0x10];
    int results = read(fd, num_str, sizeof(num_str));
    if(results < 0){
        perror("read");
        return 1;
    }
    int random_num = atoi(num_str);
    filter_3(random_num);
    filter_2(random_num);
    return 0;
}

