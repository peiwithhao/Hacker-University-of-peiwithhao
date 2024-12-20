<!--toc:start-->
- [Netfilter](#netfilter)
- [引用](#引用)
<!--toc:end-->

# Netfilter
Netfilter是一种linux内核网络过滤器
Netfilter包含几种table(`struct xt_table`),每个table用来存储不同的配置信息
每个table有多个chain(`struct xt_table_info`), chain表示对报文的拦截点，就比如一个网络层ipv4报文传过来，
他会对每个拦截点进行检测，也就是每条chain
而每个chain则包含一些rule(`struct ipt_entry`),一条rule则包含一个或多各正则匹配规则(match),和一个执行动作
其拥有以下几种功能(table):
1. filter表: 过滤报文:包含3个chain:INPUT/OUTPUT/FORWARD
2. mangle表: 修改报文， 包含5个chain
3. connection track: 会话的连接跟踪,包含2个chain,OUTPUT/PREROUTING
4. NAT: 包含三个chain, PREROUTING/OUPUT/POSTROUTIN

## 相关结构体
```c
/* Furniture shopping... */
struct xt_table {
	struct list_head list;

	/* What hooks you will enter on */
	unsigned int valid_hooks;

	/* Man behind the curtain... */
	struct xt_table_info __rcu *private; //用来存放指向`xt_table_info`的指针

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;

	u_int8_t af;		/* address/protocol family */
	int priority;		/* hook order */

	/* called when table is needed in the given netns */
	int (*table_init)(struct net *net);

	/* A unique name... */
	const char name[XT_TABLE_MAXNAMELEN];
};
```
这个结构体就是上述的表table,存在一个private字段，类型为`struct xt_table_info`且添加了`__rcu`的标识,这个标识表示在读取的时候不用加锁，
但在写的时候更新数据

```c
/* The table itself */
struct xt_table_info {
	/* Size per table */
	unsigned int size;
	/* Number of entries: FIXME. --RR */
	unsigned int number;
	/* Initial number of entries. Needed for module usage count */
	unsigned int initial_entries;

	/* Entry points and underflows */
	unsigned int hook_entry[NF_INET_NUMHOOKS];          //存放每个chains的偏移
	unsigned int underflow[NF_INET_NUMHOOKS];           //存放每个chains中default rule的偏移

	/*
	 * Number of user chains. Since tables cannot have loops, at most
	 * @stacksize jumps (number of user chains) can possibly be made.
	 */
	unsigned int stacksize;
	void ***jumpstack;

	unsigned char entries[] __aligned(8);
};
```
这里的`entries`的每个字段则存放了每个cpu所对应的专属buf,如下

           ┌──────────────┐                   ┌─────────┐
           │void  entries0├──────────────────►│CPU0 bufs│
           ├──────────────┤                   └─────────┘
           │void  entries1│
           ├──────────────┤
           │void *entries2│
           └──────────────┘

而每个`CPU bufs`里面包含的内容则是一个个`chains`数组

      ┌───────────┬──────────────┬───────────┐
      │ chains0   │   chains1    │   chains2 │
      └───────────┴──────────────┴───────────┘

然后每个chains里面则包含了一条条rules

       ┌──────┬───────┬──────┐
       │rule0 │ rule1 │ rule2│
       └──────┴───────┴──────┘

那么由于每个chains里面的rule条数都可能不同，所以需要还存在一定的偏移字段
所以`struct xt_table_info.hook_entry[]`里面就存的是在`cpu bufs`里面每个chains的起始偏移
这样就可以精准定位到每个chains下的rule
然后由于这里还存在一个默认规则字段,所以在对应的`struct xt_table.underflow[]`则存放的是每个chains的默认rule的相对偏移

然后每条rule是使用`sturct ipt_entry`来表示
```c
struct ipt_entry {
	struct ipt_ip ip;

	/* Mark with fields that we care about. */
	unsigned int nfcache;

	/* Size of ipt_entry + matches */
	__u16 target_offset;
	/* Size of ipt_entry + matches + target */
	__u16 next_offset;

	/* Back pointer */
	unsigned int comefrom;

	/* Packet and byte counters. */
	struct xt_counters counters;

	/* The matches (if any), then the target. */
	unsigned char elems[0];
};
```
而每一条rule包含多个匹配规则`struct xt_entry_match`和一个执行动作`struct xt_entry_target`
```c
struct xt_entry_match {
	union {
		struct {
			__u16 match_size;

			/* Used by userspace */
			char name[XT_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 match_size;

			/* Used inside the kernel */
			struct xt_match *match;
		} kernel;

		/* Total length */
		__u16 match_size;
	} u;

	unsigned char data[0];
};

struct xt_entry_target {
	union {
		struct {
			__u16 target_size;

			/* Used by userspace */
			char name[XT_EXTENSION_MAXNAMELEN];
			__u8 revision;
		} user;
		struct {
			__u16 target_size;

			/* Used inside the kernel */
			struct xt_target *target;
		} kernel;

		/* Total length */
		__u16 target_size;
	} u;

	unsigned char data[0];
};
```

## 通信机制
netfilter通过`setsockopt, getsockopt`来进行用户-内核的交互,
在此基础上`nftables`实现了自己的一个框架，允许不同的防火墙来实现自己和用户空间的通信函数
这里主要涉及了`nf_register_sockopt()`函数将`nf_sockopt_ops`结构体实例注册到`netfilter`管理的全局链表当中
注册完毕就可以调用`nf_sockopt_find()`来查找对应的`nf_sockopt_ops`



# 引用
[CVE-2021-22555](https://bsauce.github.io/2021/09/23/CVE-2021-22555/)


