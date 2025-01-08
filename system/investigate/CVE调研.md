# CVE分类归纳

CVE-2022-23222: 
+ 原因：eBPF verify漏洞，没有对`*_OR_NULL`指针类型进行限制，
导致攻击者可以利用漏洞在获取低权限的情况下构造而已数据执行空指针引用攻击
+ 结果: 权限提升
+ 利用exp: ebpf程序编写，[https://github.com/tr3ee/CVE-2022-23222](https://github.com/tr3ee/CVE-2022-23222)

CVE-2022-0995:
+ 原因: 观察队列事件通知子系统堆溢出漏洞
+ 结果：导致提权和逃逸
+ 利用exp：较为类似CVE-2021-22555

CVE-2021-4204:
+ 原因: eBPF verify 漏洞， 检测输入不当导致越界溢出
+ 结果: 权限提升,逃逸
+ 利用exp: 

CVE-2017-16995:
+ 原因: eBPF verify漏洞，`check_alu_op`函数检查出错
+ 结果: 提权,逃逸
+ 利用exp: [https://www.exploit-db.com/exploits/45010](https://www.exploit-db.com/exploits/45010) 

CVE-2017-5123:
+ 原因: /kernel/exit.c中的waitid的实现，在调用`unsafe_put_user()`将内核数据拷贝到用户空间地址时，
没有调用`access_ok()`检测用户空间地址的合法性，
导致实际可以往内核空间地址拷贝数据。 waitid未检测用户地址合法性 导致 null 任意地址写。
+ 结果: 提权，逃逸
+ 利用exp: 

CVE-2022-25636:
+ 原因: netfilter内核模块存在堆越界写,存在`SYS_ADMIN`特权可以造成提权
+ 结果: 导致提权,逃逸
+ 利用exp: 堆喷+条件竞争[https://github.com/chenaotian/CVE-2022-25636](https://github.com/chenaotian/CVE-2022-25636) 

CVE-2017-1000112:
+ 原因: 写越界,在构建一个UFO数据包时，内核会使用`MSG_MORE __ip_append_data()`函数来调用`ip_ufo_append_data()`并完成路径的添加。但是在这两个send()调用的过程中，添加的路径可以从UFO路径转换为非UFO路径，而这将导致内存崩溃的发生。
+ 结果: 提权，逃逸
+ 利用exp: [https://bbs.kanxue.com/thread-263114.htm](https://bbs.kanxue.com/thread-263114.htm)

CVE-2017-11176:
+ 原因: Linux内核中的 POSIX消息队列实现中存在一个UAF漏洞CVE-2017-11176。攻击者可以利用该漏洞导致拒绝服务或执行任意代码。
+ 结果: 提权，逃逸
+ 利用exp: [exp](https://raw.githubusercontent.com/lexfo/cve-2017-11176/master/cve-2017-11176.c), [https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html](https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html)

CVE-2017-6074:
+ 原因: 引用计数的改变导致double free
+ 结果: 提权，逃逸
+ 利用exp: [https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-6074](https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-6074)


CVE-2017-2384:
+ 原因:在某些Apple产品中发现了一个问题。 iOS在10.3之前受到影响。该问题涉及在“ Safari”组件的SQLite子系统中缺失的错误。它允许本地用户识别以私人浏览模式发生的网站访问。 
+ 结果: 
+ 利用exp: 


CVE-2016-9793:
+ 原因: Linux kernel 4.8.13及之前的版本中的net/core/sock.
c文件的sock_setsockopt函数存在安全漏洞，该漏洞源于程序没有正确的处理sk_sndbuf和sk_rcvbuf的负值。本地攻击者可利用该漏洞造成拒绝服务（内存损坏和系统崩溃）。

+ 结果: 提权， 逃逸
+ 利用exp: [https://nuoye-blog.github.io/2021/03/11/665d01c6/](https://nuoye-blog.github.io/2021/03/11/665d01c6/)

CVE-2016-4997:
+ 原因: 4.6.3之前，`compat ipt_so_se_set_replace`和`ip6t_so_set_replace`和`ip6t_so_set_replace setsockopt`实现了4.6.3之前的linux内核中的NetFilter子系统意外减少。
+ 结果: 提权， 逃逸
+ 利用exp: smep/smap绕过 [https://www.exploit-db.com/exploits/40049](https://www.exploit-db.com/exploits/40049)

CVE-2016-0728:
+ 原因: 整数溢出，UAF
+ 结果: 提权，逃逸
+ 利用exp: [https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits/blob/main/2016/CVE-2016-0728/cve-2016-0728.c](https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits/blob/main/2016/CVE-2016-0728/cve-2016-0728.c)

CVE-2022-0185:
+ 原因: 整数溢出
+ 结果: 提权，逃逸
+ 利用exp: 条件竞争，heap spray [https://www.willsroot.io/2022/01/cve-2022-0185.html](https://www.willsroot.io/2022/01/cve-2022-0185.html)

CVE-2021-22555:
+ 原因: 堆溢出
+ 结果: 提权，逃逸
+ 利用exp: 堆喷，[https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)
CVE-2020-14386:
+ 原因: 堆溢出
+ 结果: 提权
+ 利用exp: [https://www.anquanke.com/post/id/219203#h2-4](https://www.anquanke.com/post/id/219203#h2-4)

CVE-2017-7308:
+ 原因: 整数溢出
+ 结果: 提权，逃逸
+ 利用exp: [https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-7308/poc.c](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-7308/poc.c)

CVE-2016-5195:
+ 原因: 由于get_user_page内核函数在处理Copy-on-Write的过程中，可能产出竞态条件造成COW过程被破坏，导致出现写数据到进程地址空间内只读内存区域的机会。修改su或者passwd程序就可以达到root的目的。
+ 结果: 越权写,提权
+ 利用exp: [https://github.com/FireFart/dirtycow](https://github.com/FireFart/dirtycow)

CVE-2022-27666:
+ 原因: 此漏洞的基本逻辑是，ESP6模块中用户消息的接收缓冲区是8页的缓冲区，但是发件人可以发送大于8页的消息，这显然会产生缓冲区溢出。
+ 结果: 提权
+ 利用exp: 页级堆风水,[https://etenal.me/archives/1825](https://etenal.me/archives/1825)

CVE-2016-8655:
+ 原因:packet_set_ring函数在创建ringbuffer的时候，如果packet版本为TPACKET_V3，则会初始化struct timer_list，packet_set_ring函数返回之前，其他线程可调用setsockopt函数将packet版本设定为TPACKET_V1。前面初始化的timer未在内核队列中被注销，timer过期时触发struct timer_list中回调函数的执行，形成UAF漏洞。 
+ 结果: 提权,逃逸
+ 利用exp: [https://www.anquanke.com/post/id/85162](https://www.anquanke.com/post/id/85162)

CVE-2022-0847:
+ 原因: 标识位为清空
+ 结果: 越权写，提权
+ 利用exp: 逻辑漏洞利用[https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)

CVE-2021-3493:
+ 原因: vfs_setxattr() 函数并没有调用 cap_convert_nscap() 函数来进行校验，没有检查程序与环境的 namespace 是否一致
+ 结果: 提权
+ 利用exp: [https://bbs.kanxue.com/thread-274241.htm](https://bbs.kanxue.com/thread-274241.htm),[https://github.com/briskets/CVE-2021-3493/tree/main](https://github.com/briskets/CVE-2021-3493/tree/main)
CVE-2016-4557:
+ 原因: 在4.5.5之前，Linux内核中的内核/bpf/verifier.c中的repleast_map_fd_with_map_ptr函数无法正确维护FD数据结构，该结构允许本地用户获得特权或通过精制的服务(uaf)， BPF指令引用不正确的文件描述符。
+ 结果: 提权,逃逸
+ 利用exp: [https://www.exploit-db.com/exploits/40759](https://www.exploit-db.com/exploits/40759)

CVE-2018-18955:
+ 原因: 由于在map_write()中存在逻辑漏洞，攻击者可以通过构造恶意payload，在一些场景下，绕过权限检查达到root权限的能力。
+ 结果: 提权
+ 利用exp: 逻辑漏洞利用[https://www.freebuf.com/vuls/197122.html](https://www.freebuf.com/vuls/197122.html)


| |提权|逃逸|提权&逃逸|
|--|--|--|--|
|堆溢出|CVE-2020-14386,CVE-2022-27666 | |CVE-2022-0995, CVE-2022-25636, CVE-2017-1000112, CVE-2021-22555|
|整型溢出| | |CVE-2016-0728,CVE-2022-0185, CVE-2017-7308|
|UAF| | |CVE-2017-11176, CVE-2016-0728, CVE-2016-8655|
|Double free| | |CVE-2017-6074|
|Verifier|CVE-2022-23222| |CVE-2021-4204,CVE-2017-16995, CVE-2017-5123,CVE-2016-9793, CVE-2021-3493|
|条件竞争|CVE-2016-5195| | |
|其他|CVE-2022-0847,CVE-2018-18955 | |CVE-2016-4997|


