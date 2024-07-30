# 概述
本次实验为仅仅通过内核提供的接口来完成,从底层来进行了解,当然看源码仍然是最为强而有力的,但是我看到一半看不下去了 😸

# read/write a vector系统调用

查看man手册:
> The readv() system call reads iovcnt buffers from the file associated with the file descriptor fd into the buffers described by iov ("scatter input").

通过iov来描述的内容来批量进行性读取文件的系统调用,然后将内容存储到buffer当中


# 使用底层接口进行交互
在熔断和幽灵漏洞被发现并且解决方案落地实施后,系统调用的能耗迎来了史诗级增强,所以对于需要高性能的程序来说,减少系统调用的次数是一个不错的点子.

而本次学习的io_uring酒桶上面的readv/writev系统调用一样,用连续的队列+一次特别的系统调用来替代多次的系统调用.

io_uring中有始终绕不开的基础原理,我们需要知道的是他通过提供两个环形队列(SQ,Submission Queue)和(CQ, Completion Queue),然后用多个I/O请求队列(SQE, Submission Queue Entries)

