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


