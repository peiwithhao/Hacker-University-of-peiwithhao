#include <bits/types/struct_iovec.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>



void main(void){
    ssize_t bytes_read;
    int fd;
    char buf0[0x10];
    char buf1[0x10];
    char buf2[0x10];
    char buf3[0x10];

    int iovcnt;
    /* 构造iovec数组 */
    struct iovec iov[4];

    iov[0].iov_base = buf0;
    iov[0].iov_len = sizeof(buf0);

    iov[1].iov_base = buf1;
    iov[1].iov_len = sizeof(buf1);
    
    iov[2].iov_base = buf2;
    iov[2].iov_len = sizeof(buf2);

    iov[3].iov_base = buf3;
    iov[3].iov_len = sizeof(buf3);
    
    iovcnt = sizeof(iov)/sizeof(struct iovec);

    fd = open("./testfile", O_RDWR);

    bytes_read = readv(fd, iov, iovcnt);
    printf("%s-%s-%s-%s", buf0, buf1, buf2, buf3);

}
