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


## Use sys_*
本节源码使用linux-5.15
对于系统调用`io_uring_setup`,他用来创建sq和cq
```c

SYSCALL_DEFINE2(io_uring_setup, u32, entries,
		struct io_uring_params __user *, params)
{
	return io_uring_setup(entries, params);
}
```

我们可以看到传入的第二个参数是`struct io_uring_params`

```c
/*
 * Passed in for io_uring_setup(2). Copied back with updated info on success
 */
struct io_uring_params {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u32 sq_thread_cpu;
	__u32 sq_thread_idle;
	__u32 features;
	__u32 wq_fd;
	__u32 resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};
```
这里的io_uring_params需要我们传进去一个用户的指针,在内核源码中检测的部分似乎只用到了flags

```c

static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
	struct io_uring_params p;
	int i;

	if (copy_from_user(&p, params, sizeof(p)))
		return -EFAULT;
	for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
		if (p.resv[i])
			return -EINVAL;
	}
    //p.flags只能使用以下标识符,否则报错
	if (p.flags & ~(IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
			IORING_SETUP_SQ_AFF | IORING_SETUP_CQSIZE |
			IORING_SETUP_CLAMP | IORING_SETUP_ATTACH_WQ |
			IORING_SETUP_R_DISABLED))
		return -EINVAL;

	return  io_uring_create(entries, &p, params);
}
```

然后io_uring_create函数就负责创建cq_ring和sq_ring,
具体调用链条如下:
```c 
io_uring_setup()
    io_uring_create()    //创建struct io_uring_ctx, 这里面直接包含了sqes数组
        io_ring_ctx_alloc()     //创建struct io_uring_ctx, 并初始化其中的基础内容
        io_allocate_scq_urings()  //创建struct io_rings结构体,该结构体位于ctx中并且带有动态的cqe数组,然后分配ctx->sqes空间
```


在内核空间中创建好SQ和CQ后,用户态想要知道和使用他们该如和做呢,`io_uring_setup()`会返回一个文件句柄,
用户就可以使用mmap来将两个缓冲区来映射到用户空间,

```c
    sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, 
                  MAP_SHARED | MAP_POPULATE, 
                  s->ring_fd, IORING_OFF_SQ_RING);
```

这样我们就可以使得内存和用户之间实现交互,至于我们如何得到环形数组的参数,我们可以通过`io_uring_setup()`函数所获得的`io_uring_params`来得到


那么问题来了,我们如何使用这个io_uring呢?

我们首先需要向sqes数组中中填充我们的sqe,数据结构体如下:

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
		struct {
			__u32	cmd_op;
			__u32	__pad1;
		};
	};
	union {
		__u64	addr;	/* pointer to buffer or iovecs */
		__u64	splice_off_in;
		struct {
			__u32	level;
			__u32	optname;
		};
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
		__u32		xattr_flags;
		__u32		msg_ring_flags;
		__u32		uring_cmd_flags;
		__u32		waitid_flags;
		__u32		futex_flags;
		__u32		install_fd_flags;
		__u32		nop_flags;
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
		__u32	optlen;
		struct {
			__u16	addr_len;
			__u16	__pad3[1];
		};
	};
	union {
		struct {
			__u64	addr3;
			__u64	__pad2[1];
		};
		__u64	optval;
		/*
		 * If the ring is initialized with IORING_SETUP_SQE128, then
		 * this field is used for 80 bytes of arbitrary command data
		 */
		__u8	cmd[0];
	};
};

```

我们需要注意的是该结构体当中的opcode字段,
该字段就决定了我们要填入的sqe是为了实现什么功能,其他的字段就是为了适配该功能的sqe所需要的字段

然后当我们读取cq的时候,我们只需要读取对应用户区域map的字段即可


## io_uring_enter
这里源码取自linux5.13.13
从较为简单的路径开始讲解,此时我们已经创建了SQ和CQ,那么现在需要通过该系统调用来提交sqe

```c

SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,

		u32, min_complete, u32, flags, const void __user *, argp,
		size_t, argsz)
{
    ....
		submitted = io_submit_sqes(ctx, to_submit);
    ...
}
```
传入了类型为`struct io_uring_ctx`的变量,这个也是`io_uring_setup`返回文件fd的private_data

我们继续向下跟进

```c
static int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr)
{
		req = io_alloc_req(ctx);    //分配请求,我们将使用它来存取sqe
    ...
		sqe = io_get_sqe(ctx);      //获取sqring中的sqe 
    ...
		if (io_submit_sqe(ctx, req, sqe))
			break;
    ...
}
```

然后我们来到`io_submit_sqe`
```c

static int io_submit_sqe(struct io_ring_ctx *ctx, struct io_kiocb *req,
			 const struct io_uring_sqe *sqe)
{
    ...
	ret = io_req_prep(req, sqe);
    ...
			io_queue_sqe(req);
    ...
}
```

这里只留了两个函数进行解释,其中`io_req_prep()`函数是为了使用sqe中的字段来填充req的字段`struct io_provide_buf`

然后后面的`io_queue_sqe(req)`函数则在真正对该IO进行操作

```c
static void io_queue_sqe(struct io_kiocb *req)
{
    ...
		__io_queue_sqe(req);
    ...
}
```
然而这里是封装,接着看
```c
static void __io_queue_sqe(struct io_kiocb *req)
{
    ...
	ret = io_issue_sqe(req, IO_URING_F_NONBLOCK|IO_URING_F_COMPLETE_DEFER);
    ...
}

```
这里调用io_issue_sqe来通过opcode判断调用哪个函数

```c
static int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
{
    ...
	switch (req->opcode) {
	case IORING_OP_NOP:
		ret = io_nop(req, issue_flags);
		break;
	case IORING_OP_READV:
	case IORING_OP_READ_FIXED:
	case IORING_OP_READ:
    ...
}
```
至此内核中对于IO函数处理的大致流程结束

