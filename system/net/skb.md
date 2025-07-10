# sk_buff
本节大部分的知识来源于[Linux kernel doc](https://docs.kernel.org/networking/skbuff.html)
他用来表示一个网络流量包

在内核中的数据结构如下:

```c
struct sk_buff {
    ...
	/* These elements must be at the end, see alloc_skb() for details.  */
	sk_buff_data_t		tail;
	sk_buff_data_t		end;
	unsigned char		*head,
				*data;
	unsigned int		truesize;
	refcount_t		users;
    ...
};
```

> [!NOTE]
> 这个结构体专门用来存放元数据，对于网络包的数据则存放在其他缓冲区当中


```text
                                ---------------
                               | sk_buff       |
                                ---------------
   ,---------------------------  + head
  /          ,-----------------  + data
 /          /      ,-----------  + tail
|          |      |            , + end
|          |      |           |
v          v      v           v
 -----------------------------------------------
| headroom | data |  tailroom | skb_shared_info |
 -----------------------------------------------
                               + [page frag]
                               + [page frag]
                               + [page frag]
                               + [page frag]       ---------
                               + frag_list    --> | sk_buff |
                                                   ---------
```

而`sk_buff.head`指向主要的`head buffer`,而这个head buffer分为两个部分
+ data bufer: 包含头部，有时候包含一些载荷,这一部分由常见的helper程序使用，例如`skb_put(), skb_pull()`
+ shared info: 只读数据的一些数组指针



# 引用
[https://docs.kernel.org/networking/skbuff.html](https://docs.kernel.org/networking/skbuff.html) 
