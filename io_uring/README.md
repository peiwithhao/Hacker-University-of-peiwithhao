# 概述
本次实验为仅仅通过内核提供的接口来完成,从底层来进行了解,当然看源码仍然是最为强而有力的,但是我看到一半看不下去了 😸

# read/write a vector系统调用

查看man手册:
> The readv() system call reads iovcnt buffers from the file associated with the file descriptor fd into the buffers described by iov ("scatter input").

通过iov来描述的内容来批量进行性读取文件的系统调用,然后将内容存储到buffer当中


# 使用底层接口进行交互
在熔断和幽灵漏洞被发现并且解决方案落地实施后,系统调用的能耗迎来了史诗级增强,所以对于需要高性能的程序来说,减少系统调用的次数是一个不错的点子.

而本次学习的io_uring酒桶上面的readv/writev系统调用一样,用连续的队列+一次特别的系统调用来替代多次的系统调用.

<<<<<<< HEAD
io_uring中有始终绕不开的基础原理,我们需要知道的是他通过提供两个环形队列(SQ,Submission Queue)和(CQ, Completion Queue),然后用多个I/O请求队列(SQE, Submission Queue Entries)来填充

之后我们的任务就是使用`io_uring_setup`系统调用来创建队列,然后添加SQE到SQ,
然后读取CQ即可

## Completion Queue Entry
下面就是完成队列条目的数据结构,下面的结构包含通过SQE实例请求操作的结果
```c
/*
 * IO completion data structure (Completion Queue Entry)
 */
struct io_uring_cqe {
	__u64	user_data;	/* sqe->data submission passed back */
	__s32	res;		/* result code for this event */
	__u32	flags;
};

```
这里需要注意的是CQE的顺序并不是由SQE的传递顺序决定的,因为只有这样能尽情的释放我们的异步IO的能力,
设想如果我们此时若按照SQE的顺序来填充CQE的话,那相较之于前面同步I/O不就是五十步笑百步了.
那么现在唯一的Point就是我们如何知道CQE对应的是哪条SQE呢,这里先给出答案,使用user_data字段来区分,具体见下文

## Submission Queue Entry

比CQE会复杂的多,如下:
 

```c 

/*
 * IO submission data structure (Submission Queue Entry)
 */
struct io_uring_sqe {
	__u8	opcode;		/* type of operation for this sqe */
	__u8	flags;		/* IOSQE_ flags */
	__u16	ioprio;		/* ioprio for the request */
	__s32	fd;		/* file descriptor to do IO on */
	union {
		__u64	off;	/* offset into file */
		__u64	addr2;
	};
	union {
		__u64	addr;	/* pointer to buffer or iovecs */
		__u64	splice_off_in;
	};
	__u32	len;		/* buffer size or number of iovecs */
	union {
		__kernel_rwf_t	rw_flags;
		__u32		fsync_flags;
		__u16		poll_events;	/* compatibility */
		__u32		poll32_events;	/* word-reversed for BE */
		__u32		sync_range_flags;
		__u32		msg_flags;
		__u32		timeout_flags;
		__u32		accept_flags;
		__u32		cancel_flags;
		__u32		open_flags;
		__u32		statx_flags;
		__u32		fadvise_advice;
		__u32		splice_flags;
		__u32		rename_flags;
		__u32		unlink_flags;
		__u32		hardlink_flags;
	};
	__u64	user_data;	/* data to be passed back at completion time */
	/* pack this to avoid bogus arm OABI complaints */
	union {
		/* index into fixed buffers, if used */
		__u16	buf_index;
		/* for grouped buffer selection */
		__u16	buf_group;
	} __attribute__((packed));
	/* personality to use, if used */
	__u16	personality;
	union {
		__s32	splice_fd_in;
		__u32	file_index;
	};
	__u64	__pad2[2];
};
```

根据[`Lord of IO_uring`](https://web.archive.org/web/20221119023652/https://unixism.net/loti/low_level.html)所说,这些字段看似复杂,
但实际上运用起来只会使用少部分 🐶


io_uring中有始终绕不开的基础原理,我们需要知道的是他通过提供两个环形队列(SQ,Submission Queue)和(CQ, Completion Queue),然后用多个I/O请求队列(SQE, Submission Queue Entries)




