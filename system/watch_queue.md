# Watch Queue 观察队列
启用观察队列需要开启标识`CONFIG_WATCH_QUEUE`
该工具表现为以特殊方式打开的管道pipe,管道内部的`pipe_buffer`用来存储通知消息
然后用户使用read进行读取
# Message Structure
消息结构体如下:
```c
/*
 * Notification record header.  This is aligned to 64-bits so that subclasses
 * can contain __u64 fields.
 */
struct watch_notification {
	__u32			type:24;	/* enum watch_notification_type */
	__u32			subtype:8;	/* Type-specific subtype (filterable) */
	__u32			info;
#define WATCH_INFO_LENGTH	0x0000007f	/* Length of record */
#define WATCH_INFO_LENGTH__SHIFT 0
#define WATCH_INFO_ID		0x0000ff00	/* ID of watchpoint */
#define WATCH_INFO_ID__SHIFT	8
#define WATCH_INFO_TYPE_INFO	0xffff0000	/* Type-specific info */
#define WATCH_INFO_TYPE_INFO__SHIFT 16
#define WATCH_INFO_FLAG_0	0x00010000	/* Type-specific info, flag bit 0 */
#define WATCH_INFO_FLAG_1	0x00020000	/* ... */
#define WATCH_INFO_FLAG_2	0x00040000
#define WATCH_INFO_FLAG_3	0x00080000
#define WATCH_INFO_FLAG_4	0x00100000
#define WATCH_INFO_FLAG_5	0x00200000
#define WATCH_INFO_FLAG_6	0x00400000
#define WATCH_INFO_FLAG_7	0x00800000
};
```
通知消息头部：
1. type: 表示通知记录的来源
2. subtype: 标识来自该来源的记录类型
3. info: 表示多重信息, 包括(消息长度, 监控者的调用ID, 特定字段)


# Watch List
指订阅了某个对象的观察者列表

```c
void init_watch_list(struct watch_list *wlist,
                     void (*release_watch)(struct watch *wlist));
```
初始化watch_list, 第二个参数是当观察者被销毁将要调用的回调函数


```c
void remove_watch_list(struct watch_list *wlist);
```
删除订阅并销毁`watch_list`本身


# Watch Queue
该队列由用户程序分配的缓冲区，用于写入通知记录

```c
struct watch_queue *get_watch_queue(int fd);
```
fd由用户传递给内核


```c
void put_watch_queue(struct watch_queue *wqueue);
```
用来丢弃得到的`watch_queue`

# filter
一旦创建了通知队列，就可以创建filter来限制获取的数据
```c
struct watch_notification_filter filter = {
        ...
};
ioctl(fd, IOC_WATCH_QUEUE_SET_FILTER, &filter)
```


这里的过滤器结构体包含了多个过滤规则

```c
struct watch_notification_filter {
    __u32   nr_filters;
    __u32   __reserved;
    struct watch_notification_type_filter filters[];
};

struct watch_notification_type_filter {
        __u32   type;
        __u32   info_filter;
        __u32   info_mask;
        __u32   subtype_filter[8];
};
```



