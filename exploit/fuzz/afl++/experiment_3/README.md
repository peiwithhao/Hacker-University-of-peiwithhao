本次实验将fuzz tcpdump包分析器

## environment
OS: ubuntu20.04LTS
LLVM: 13
afl++: latest  
tcpdump 4.9.2
libpcap 1.8.1

## TCPdump 下载
```sh
$ wget https://www.tcpdump.org/release/libpcap-1.8.1.tar.gz
$ wget https://www.tcpdump.org/release/tcpdump-4.9.2.tar.gz
```

在编译tcpdump时还需要安装`libpcap`这样一个包

然后就使用`afl-clang-fast`来分别编译这两个包，这里需要设置的环境变量如下：
```sh
$ export CC=afl-clang-fast
$ export CXX=afl-clang-fast++
$ export AFL_USE_ASAN=1
```
然后先后编译`libpcap,tcpdump`即可
在这里我在`configure`中明明加上了`--prefix=$HOME/install`但发现他还是把编译结果放在了当前目录，不过也无伤大雅

```sh
peiwithhao@aflzzer-mechine:~/fuzzing_tcpdump/tcpdump-4.9.2$ ./tcpdump --help
tcpdump version 4.9.2
libpcap version 1.8.1
OpenSSL 1.1.1f  31 Mar 2020
Compiled with AddressSanitizer/CLang.
Usage: tcpdump [-aAbdDefhHIJKlLnNOpqStuUvxX#] [ -B size ] [ -c count ]
		[ -C file_size ] [ -E algo:secret ] [ -F file ] [ -G seconds ]
		[ -i interface ] [ -j tstamptype ] [ -M secret ] [ --number ]
		[ -Q in|out|inout ]
		[ -r file ] [ -s snaplen ] [ --time-stamp-precision precision ]
		[ --immediate-mode ] [ -T type ] [ --version ] [ -V file ]
		[ -w file ] [ -W filecount ] [ -y datalinktype ] [ -z postrotate-command ]
		[ -Z user ] [ expression ]
```

## 初始测试样例
tcpdump用法十分多样，首先就可以指定网卡,然后从我的主机ping的话就会出现如下输出
```sh
$ tcpdump -i enp1s0
17:32:26.819045 IP _gateway > aflzzer-mechine: ICMP echo request, id 1, seq 4, length 64
17:32:26.819104 IP aflzzer-mechine > _gateway: ICMP echo reply, id 1, seq 4, length 64
17:32:27.832217 IP _gateway > aflzzer-mechine: ICMP echo request, id 1, seq 5, length 64
17:32:27.832265 IP aflzzer-mechine > _gateway: ICMP echo reply, id 1, seq 5, length 64
17:32:28.525515 STP 802.1d, Config, Flags [none], bridge-id 8000.52:54:00:1f:7e:a0.8001, length 35
```
那么我们难不成fuzz的话需要在网卡上面不断进行输入吗，那显然是不太现实的
然而tcpdump还有一个用法可以接受文件
```sh
$ tcpdump -r *.pcap
```
这类文件是用于存储网络数据包的文件格式。它通常由网络分析工具（如 tcpdump、Wireshark 等）生成，包含捕获的网络流量数据

因此我们可以将此类文件进行输入，而输入样例我们可以到`tcpdump`的官网找到测试用例

## 开始fuzz
本次fuzz跑了很久才出一两个crash,当跑出来之后直接运行如下
```sh
==2052==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6120000002d7 at pc 0x000000387586 bp 0x7ffc6d428640 sp 0x7ffc6d427de8
READ of size 4 at 0x6120000002d7 thread T0
    #0 0x387585 in MemcmpInterceptorCommon(void*, int (*)(void const*, void const*, unsigned long), void const*, void const*, unsigned long) crtstuff.c
    #1 0x387a79 in memcmp (/home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/tcpdump+0x387a79)
    #2 0x492644 in bootp_print /home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/./print-bootp.c:382:6
    #3 0x515228 in ip_print_demux /home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/./print-ip.c:402:3
    #4 0x518e6a in ip_print /home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/./print-ip.c:673:3
    #5 0x4cf10e in ethertype_print /home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/./print-ether.c:333:10
    #6 0x4cdc1e in ether_print /home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/./print-ether.c:236:7
    #7 0x42b94a in pretty_print_packet /home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/./print.c:332:18
    #8 0x42b94a in print_packet /home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/./tcpdump.c:2497:2
    #9 0x6e5706 in pcap_offline_read /home/peiwithhao/fuzzing_tcpdump/libpcap-1.8.1/./savefile.c:527:4
    #10 0x6e5706 in pcap_loop /home/peiwithhao/fuzzing_tcpdump/libpcap-1.8.1/./pcap.c:890:8
    #11 0x4262d4 in main /home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/./tcpdump.c:2000:12
    #12 0x7f6dc115e082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/../csu/libc-start.c:308:16
    #13 0x36f0ad in _start (/home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/tcpdump+0x36f0ad)

0x6120000002d7 is located 0 bytes to the right of 279-byte region [0x6120000001c0,0x6120000002d7)
allocated by thread T0 here:
    #0 0x3eb85d in malloc (/home/peiwithhao/fuzzing_tcpdump/tcpdump-4.9.2/tcpdump+0x3eb85d)
    #1 0x743bed in pcap_check_header /home/peiwithhao/fuzzing_tcpdump/libpcap-1.8.1/./sf-pcap.c:401:14

SUMMARY: AddressSanitizer: heap-buffer-overflow crtstuff.c in MemcmpInterceptorCommon(void*, int (*)(void const*, void const*, unsigned long), void const*, void const*, unsigned long)
Shadow bytes around the buggy address:
  0x0c247fff8000: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0c247fff8010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c247fff8020: 00 00 00 00 00 00 00 00 00 00 00 00 00 07 fa fa
  0x0c247fff8030: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0c247fff8040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c247fff8050: 00 00 00 00 00 00 00 00 00 00[07]fa fa fa fa fa
  0x0c247fff8060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c247fff8070: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c247fff8080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c247fff8090: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c247fff80a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==2052==ABORTING
```
这里发现问题出在`bootp_print`里面，里面调用`memcmp`传递的参数所比较的内容超出了最初分配的界限,最终造成了越界读，也就是CVE-2017-13028
解决方法即在比较之前插入检测大小的代码,这里是[commit](https://github.com/the-tcpdump-group/tcpdump/commit/29e5470e6ab84badbc31f4532bb7554a796d9d52)
而这里还发现了一个越界读错误那就是在`ospf6_print_lshdr`打印数据结构内容时出现了越界，同样是有Asan报错







