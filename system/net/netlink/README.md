<!--toc:start-->
- [netlink 极速释义](#netlink-极速释义)
- [Kernel connector](#kernel-connector)
- [参考](#参考)
<!--toc:end-->

# netlink 极速释义
```sh
NAME
       netlink - communication between kernel and user space (AF_NETLINK)

SYNOPSIS
       #include <asm/types.h>
       #include <sys/socket.h>
       #include <linux/netlink.h>

       netlink_socket = socket(AF_NETLINK, socket_type, netlink_family);
```
注意这里的使用仅仅面向于用户

通常用来作为ioctl的替代方案

下面解释每个参数含义
+ socket_type: 可以是`SOCK_RAW, SOCK_DGRAM`, netlink协议不群分数据包和原始socket
+ socket_family:选择了将要交互的内核模块或者是`netlink_group`, 具体内容可以去man手册(man 7 netlink)或者在内核源码中`include/uapi/linux/netlink.h`中查看
```c

#define NETLINK_ROUTE		0	/* Routing/device hook				*/
#define NETLINK_UNUSED		1	/* Unused number				*/
#define NETLINK_USERSOCK	2	/* Reserved for user mode socket protocols 	*/
#define NETLINK_FIREWALL	3	/* Unused number, formerly ip_queue		*/
#define NETLINK_SOCK_DIAG	4	/* socket monitoring				*/
#define NETLINK_NFLOG		5	/* netfilter/iptables ULOG */
#define NETLINK_XFRM		6	/* ipsec */
...
```
这些属于是`Classic Nelink`,这部分的netlink的实现是对于子系统的ID静态分配
而在2005年推出的`Generic Netlink`则允许动态注册子系统(和子系统ID分配),自省并简化接口内核端的实现


# Netlink消息头部

Netlink 消息始终以`struct nlmsghdr`开头,然后后面跟特定协议的head ,`Generic Netlink`则是`struct genlmsghdr`
```c
/**
 * struct nlmsghdr - fixed format metadata header of Netlink messages
 * @nlmsg_len:   Length of message including header
 * @nlmsg_type:  Message content type
 * @nlmsg_flags: Additional flags
 * @nlmsg_seq:   Sequence number
 * @nlmsg_pid:   Sending process port ID
 */
struct nlmsghdr {
	__u32		nlmsg_len;
	__u16		nlmsg_type;
	__u16		nlmsg_flags;
	__u32		nlmsg_seq;
	__u32		nlmsg_pid;
};
struct genlmsghdr {
	__u8	cmd;
	__u8	version;
	__u16	reserved;
};
```

其中,在`Classic Netlink`中，`struct nmmsghdr.nlmsg_type`代表了制定内核子系统的操作,
而`Generic Netlink`中，由于他需要通过一个头来代表多种不同的子系统，所以这里的`struct nlmsghdr.nlmsg_type`表示子系统
`struct genlmsghdr.cmd`则表示指定内核子系统的操作

# Netlink 信息交换
信息交换主要有以下三种类型
1. do: 执行单一动作
2. dump: dump信息
3. multicast: 获取异步通知

异步通知由内核发出，由订阅的用户态代码接受，而`do, dump`请求由用户发起

`struct nlmsghdr.nlmsg_flags`有以下选项
1. do: `NLM_F_REQUEST | NLM_F_ACK`
2. dump: `NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP`

`struct nlmsghdr.nlmsg_seq`字段的目的是匹配请求的响应，异步通知这个字段为0
`struct nlmsghdr.nlmsg_pid`相当于Netlink中的地址，与内核通信的时候可以将该字段设置为0



# Kernel connector
在linux5.2和更早期的版本,该部分功能体现在`socket_family`中,我们可以通过指定该参数为`NETLINK_CONNECTOR`来使用,但是在较新版本中进行了修改
在以往版本中我们可以到`Documentation/driver-api/connector.rst(or Documentation/connector/connector.*)`查看

内核文档提供的代码释义也可以到`samples/connector/`中查看

接下来介绍几种内核接口:
```c
/**
 * cn_add_callback() - 注册回调函数.
 *
 * @id:		独特的connector用户标识符.对于合法的内核用户来说他必须在connector中注册
 * @name:	connector 的回调符号名
 * @callback:	connector 的回调函数, 参数是%cn_msg和发送者的凭据
 */
int cn_add_callback(const struct cb_id *id, const char *name,
		    void (*callback)(struct cn_msg *, struct netlink_skb_parms *));

/**
 * cn_del_callback() - 注销callback.
 *
 * @id:		独特的connector用户标识符
 */
void cn_del_callback(const struct cb_id *id);


/**
 * cn_netlink_send_mult - 给指定的groups发送信息.
 *
 * @msg: 	消息头部(伴有连接的数据)
 * @len:	发送消息@msg的个数.
 * @portid:	目的端口.如果非0则发送到指定端口
 * @group:	目的组.
 *      如果@protid和@group是0,则将在所有注册的connector用户中搜索适当的组,
 *      并传递消息到具有与@msg中相同ID的用户创建的组,如果@group不为0
 *      则消息传递到指定的组
 * @gfp_mask:	GFP mask.
 *
 * If there are no listeners for given group %-ESRCH can be returned.
 */
int cn_netlink_send_mult(struct cn_msg *msg, u16 len, u32 portid, u32 group, gfp_t gfp_mask);

/**
 * cn_netlink_send - Sends message to the specified groups.
 *
 * @msg:	message header(with attached data).
 * @portid:	destination port.
 *		If non-zero the message will be sent to the given port,
 *		which should be set to the original sender.
 * @group:	destination group.
 * 		If @portid and @group is zero, then appropriate group will
 *		be searched through all registered connector users, and
 *		message will be delivered to the group which was created
 *		for user with the same ID as in @msg.
 *		If @group is not zero, then message will be delivered
 *		to the specified group.
 * @gfp_mask:	GFP mask.
 *
 * It can be safely called from softirq context, but may silently
 * fail under strong memory pressure.
 *
 * If there are no listeners for given group %-ESRCH can be returned.
 */
int cn_netlink_send(struct cn_msg *msg, u32 portid, u32 group, gfp_t gfp_mask);
```
# 内核samples
位于`samples/connector`
需要启用`CONFIG_CONNECTOR and CONFIG_SAMPLES`

这里仍须我们主动编译当前目录的驱动,需要重写一下当前的Makefile

```Makefile
KERNELDIR := ../..
CURRENT_PATH := $(shell pwd)
KDIR := ../..

obj-m := cn_test.o

build: kernel_modules

kernel_modules:
	$(MAKE) -C $(KDIR) M=$(CURRENT_PATH) modules
	rm *.mod*
clean:
	$(MAKE) -C $(KDIR) M=$(CURRENT_PATH) clean
```
然后复制到文件系统,然后启动时插入模块`*.ko`即可




# 用户空间使用

```c
struct sockaddr_nl {
	__kernel_sa_family_t	nl_family;	/* AF_NETLINK	*/
	unsigned short	nl_pad;		/* zero		*/
	__u32		nl_pid;		/* port ID	*/
       	__u32		nl_groups;	/* multicast groups mask */
};
```


一般默认情况下不允许人们将数据发送到除1之外的netlink组,所以如果希望使用具有不同组号的netlink套接字,则用户空间必须首先订阅该组,例子如下:

```c
    nl_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_fd == -1){
        perror("socket");
        return -1;
    }
    /* 配置sockaddr_nl */
    l_local.nl_family = AF_NETLINK;
    l_local.nl_groups = CN_IDX_PROC;
    l_local.nl_pid = getpid();
```

首先我们需要创建套接字,然后将其绑定在某个组,这里使用`CN_IDX_PROC`作为例子,如果希望自己实现一个额外的驱动来进行学习仿照`samples/connector`编写

```c
    if(bind(sock_fd, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1){
        perror("bind");
        close(nl_fd);
        return -1;
    }
```

在绑定完之后就可以与内核进行交互,之后就是对于交互格式的分析

在正式开始传递信息时仍需要先启动连接器
我们的消息格式为`struct nlmsghdr + struct cn_msg + cn_msg->data[]`,
当我们是开启连接时,我们发送的`cn_msg->data`内容为一个枚举类型
```c
/*
 * Userspace sends this enum to register with the kernel that it is listening
 * for events on the connector.
 */
enum proc_cn_mcast_op {
	PROC_CN_MCAST_LISTEN = 1,
	PROC_CN_MCAST_IGNORE = 2
};
```
这个枚举类型作为data发送消息来告诉内核用户空间是否在监听内容

然后调用sendmsg来发送消息

那么进行连接之后呢,接受消息也是同样的套路,此时就可以自定义响应处理
我们只需要接收消息
```c
...
    ret = recvmsg(nl_fd, &msg, 0);
...
```
注意这里如果是使用上面的消息结构就需要使用`recv()`来接受消息
接收后获取`nl_fd->cn_msg`
然后`cn_msg`里面的data结构体的类型为`struct proc_event`(`cn_proc`类型下)
之后我们就可以判断`proc_event->what`来对不同事件分别进行处理

# 参考

[https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html](https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html)
[https://zhuanlan.zhihu.com/p/530687422](https://zhuanlan.zhihu.com/p/530687422)
[https://www.kernel.org/doc/html/next/driver-api/connector.html](https://www.kernel.org/doc/html/next/driver-api/connector.html)
[https://blog.csdn.net/Longyu_wlz/article/details/108940087](https://blog.csdn.net/Longyu_wlz/article/details/108940087)
[https://blog.csdn.net/Longyu_wlz/article/details/108879110](https://blog.csdn.net/Longyu_wlz/article/details/108879110)






