# 概述
本次实验为仅仅通过内核提供的接口来完成,从底层来进行了解,当然看源码仍然是最为强而有力的,但是我看到一半看不下去了 😸

# read/write a vector系统调用

查看man手册:
> The readv() system call reads iovcnt buffers from the file associated with the file descriptor fd into the buffers described by iov ("scatter input").

通过iov来描述的内容来批量进行性读取文件的系统调用,然后将内容存储到buffer当中
