<!--toc:start-->
- [Volume I:安装syzkaller](#volume-i安装syzkaller)
  - [Chapter I:安装Go编译器](#chapter-i安装go编译器)
  - [Chapter II:安装syzkaller](#chapter-ii安装syzkaller)
  - [Chapter III:安装C编译器](#chapter-iii安装c编译器)
  - [Chapter IV:构建guset VM](#chapter-iv构建guset-vm)
- [Volume II:syzkaller 启动!](#volume-iisyzkaller-启动)
- [Volume III:syzkaller基本原理](#volume-iiisyzkaller基本原理)
  - [Chapter I:系统调用描述](#chapter-i系统调用描述)
    - [1.程序](#1程序)
    - [1.添加新的系统调用](#1添加新的系统调用)
  - [Chapter II:Syzlang学习](#chapter-iisyzlang学习)
    - [1.Ints](#1ints)
    - [2.Structs](#2structs)
    - [3.Resorces](#3resorces)
- [Volume IV:syzkaller自行编写系统调用](#volume-ivsyzkaller自行编写系统调用)
- [Reference](#reference)
<!--toc:end-->

# Volume I:安装syzkaller

安装syzkaller需要以下几个条件:
1. Go 编译器和 syzkaller 本身
2. 具有覆盖率支持的 C 编译器
3. 添加了覆盖范围的 Linux 内核
4. 虚拟机或物理设备

## Chapter I:安装Go编译器
首先是安装go编译器,这里我们可以直接去[官网](https://go.dev/dl/)下载最新版
```shell
$ wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
$ tar xvf go1.22.3.linux-amd64.tar.gz 
$ export GOROOT=`pwd`/go
$ export PATH=$GOROOT/bin:$PATH
```
## Chapter II:安装syzkaller
然后我们下载syzkaller
```shell
$ git clone https://github.com/google/syzkaller
$ cd syzkaller
$ make
```
编译后我们的二进制文件就放在`bin/`目录下

## Chapter III:安装C编译器
Syzkaller是一个覆盖率引导的模糊器,因此他需要具有覆盖率支持的内核,所以需要最新的GCC版本,官方文档所说覆盖支持已经提交给了GCC,在其GCC6.1.0或更高的版本当中发布

## Chapter IV:构建guset VM
这里直接采用qemu来构建,其中内核镜像我们可以直接到[linux官网](kernel.org)下载,其中要注意的点就是要加上以下config,如果在后面启动的时候出现报错,比如说网络无法启动的话,这里更推荐使用官方所给出的[syzbot配置文件](https://github.com/google/syzkaller/blob/master/docs/linux/kernel_configs.md#syzkaller-features),除此之外我们也可以从syzkaller官方的[troubleshooting](https://github.com/google/syzkaller/blob/master/docs/linux/troubleshooting.md)来找到解决办法:
```config
CONFIG_KCOV=y
CONFIG_DEBUG_INFO=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y'
```
然后我们正常编译即可
```shell
$ make bzImage -j10
```

磁盘镜像的话起初打算使用busybox来简单制作一个能用就行的镜像,但是似乎syzkaller后期还需要进行ssh连接,因此采用了大多数师傅所用到的`debootstrap`来构建镜像文件,然后使用官方给出的镜像构建脚本来创建
```sh
$ sudo apt install debootstrap
$ mkdir image
$ cd image
$ wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
$ chmod +x create-image.sh
$ ./create-image.sh

```
在构建起磁盘镜像后我们就可以使用qemu来启动
```shell

#!/bin/bash
qemu-system-x86_64 \
        -m 2G \
        -smp 2 \
        -kernel ./bzImage \
        -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
        -drive file=./bullseye.img,format=raw \
        -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
        -net nic,model=e1000 \
        -enable-kvm \
        -nographic \
        -pidfile vm.pid \
        2>&1 | tee vm.log
```

然后我们现在启动后也可以使用ssh进行连接
```shell
$ ssh -i ./bullseye.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost
```

![image-20240531144443247](./syzkaller-part-I/image-20240531144443247.png)

# Volume II:syzkaller 启动!
首先编写syzkaller的启动配置文件,官方给出的例子如下:
```config
{
	"target": "linux/amd64",
	"http": "127.0.0.1:56741",
	"workdir": "$GOPATH/src/github.com/google/syzkaller/workdir",
	"kernel_obj": "$KERNEL",
	"image": "$IMAGE/bullseye.img",
	"sshkey": "$IMAGE/bullseye.id_rsa",
	"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
	"procs": 8,
	"type": "qemu",
	"vm": {
		"count": 4,
		"kernel": "$KERNEL/arch/x86/boot/bzImage",
		"cpu": 2,
		"mem": 2048
	}
}
```
这里需要将一些变量设置为实际值,然后将该文件保存到syzkaller目录下

```shell

{
        "target": "linux/amd64",
        "http": "127.0.0.1:56741",
        "workdir": "/home/peiwithhao/gopath/src/github.com/google/syzkaller/bin/workdir",
        "kernel_obj": "$KERNEL",
        "image": "/home/peiwithhao/image/bullseye.img",
        "sshkey": "/home/peiwithhao/image/bullseye.id_rsa",
        "syzkaller": "/home/peiwithhao/gopath/src/github.com/google/syzkaller",
        "procs": 8,
        "type": "qemu",
        "vm": {
                "count": 4,
                "kernel": "/home/pewithhao/Downloads/linux-5.17.9/arch/x86/boot/bzImage",
                "cpu": 2,
                "mem": 2048,
                "qemu_args":"-enable-kvm"
        }
}
```

现在先别谈什么原理,我们先正常启动syzkaller,隔着狠狠的发发发

![姿态：发发发哔哩哔哩bilibili](./syzkaller-part-I/images.jpeg)



```shell
$ ./bin/syz-manager -config=config.cfg
```

![image-20240605114205236](./syzkaller-part-I/image-20240605114205236.png)

但是跑了半天并没有报出什么漏洞,难不成是这个版本太稳定了?

所以接下来我们尝试修改策略,这涉及到syzkaller的特殊语法

# Volume III:syzkaller基本原理

由于跑了半天没有爆出什么漏洞,现在要找找自身的问题,所以我们此时可以从原理出发了解一下syzkaller到底做了什么

首先的首先,我们先从官方文档了解这一切:

![Process structure for syzkaller](./syzkaller-part-I/process_structure.png)

下面来逐个进行解释:

+ syz-manager的作用:

  1. 启动/重新启动/监控虚拟机实例
  2. 实际的模糊测试过程(输入生成,变异,最小化等)
  3. 持久语料库和崩溃存储

  它运行在具有稳定内核的主机上,不会遇到白噪声模糊器负载

+ syz-fuzzer由syz-manager启动,且每个虚拟机内一个,syz-fuzzer通过RPC与syz-manger进行通信,用来接收必须执行的程序并报告结果(错误状态,收集的覆盖率等等)

+ syz-executor进程用来执行一个输入(一系列系统调用).它接受从syz-fuzzer进程执行的程序并将结果发送回.它被设计的尽量简单(不干扰模糊测试过程)


## Chapter I:系统调用描述
syzkaller使用系统调用接口的声明性描述来操作程序,如下:
```c
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd read(fd fd, buf buffer[out], count len[buf])
close(fd fd)
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```
其中描述被存放在syzkaller项目目录`sys/$OS/*.txt`里面,而这种系统调用描述语言在[官方文档](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md)有对应描述
语言又叫做`syzlang`,这里存在官方文档中更正式的[描述语法](https://github.com/google/syzkaller/blob/master/prog/prog.go)
### 1.程序
好了我们现在已经知道fuzz用户需要提供一个基于syzlang语法的描述,那么该描述有什么用呢,
被转变好的描述用来生成,变异,执行,最小化,序列化和反序列化程序
一个程序是具有具体参数的系统调用序列,如下:
```c
r0 = open(&(0x7f0000000000)="./file0", 0x3, 0x9)
read(r0, &(0x7f0000000000), 42)
close(r0)
```
其中具体的操作,syzkaller使用in-memory的类AST的表示形式,由`prog/prog.go`来进行转化,该表示用来分析,生成,变异,最小化,验证等程序


### 1.添加新的系统调用

首先我们需要知道的是目前所有系统调用描述符都是手动编写的.还没有一种完全自动化的方法来生成描述.
要启用新的内核接口的模糊测试要遵循以下几步:
1. 研究接口,找出使用它需要哪些系统调用
    + Website Searching
    + Documentation Searching
    + Kernel Dir Searching
    + Source Code Comment Searching
    + git commit Searching
    + Source Code Searching
2. 根据[描述语法](https://github.com/google/syzkaller/blob/master/prog/prog.go)将此接口的声明性描述添加到相应的文件中
    + `sys/linux/<subsystem>.txt`文件保存着对应子系统的系统调用,例如cgroup.txt等等
    + `sys/linux/sys.txt`包含更加通用的系统调用描述
    + 可以将全新的子系统添加为`sys/linux/<new>.txt`
    + 如果子系统描述分散在多个文件,需要在每个文件的名称前添加子系统的名称前缀,例如`dev_*.txt`来描述`/dev/`设备
3. 添加/更改描述后运行:
    ```shell
    make extract TARGETOS=linux SOURCEDIR=$KSRC
    make generate
    make
    ```
4. syzkaller,启动!



## Chapter II:Syzlang学习
下列是系统调用描述的伪形式语法:
```syzlang
syscallname "(" [arg ["," arg]*] ")" [type] ["(" attribute* ")"]
arg = argname type
argname = identifier
type = typename [ "[" type-options "]" ]
typename = "const" | "intN" | "intptr" | "flags" | "array" | "ptr" |
	   "string" | "strconst" | "filename" | "glob" | "len" |
	   "bytesize" | "bytesizeN" | "bitsize" | "vma" | "proc" |
	   "compressed_image"
type-options = [type-opt ["," type-opt]]
```
整体的构成主要是为了描述一个系统调用:
其中我们可以在官方文档看到一个使用syzlang的系统调用例子
```syzlang
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd
read(fd fd, buf buffer[out], count len[buf])
close(fd fd)
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```
这里我们发现在每个arg的后面都会带有type-options来对其进行限制


这里主要解释type字段的构成,他由`typename ["["type-options "]"]`构成,因此下面我们着重介绍每个`typename`所对应的`type-options`


下面介绍各个字段:
+ `type-options`:
    + `opt`:最常见的类型选项
    + `const`:整形常量,
        + value, 并且强调类型(e.g. const [33, intN/intptr] )
    + `intN/intptr`:不带特殊意义的整形值
        + 值的范围 (e.g. intN/intptr [5:10])
        + 对于一个flags描述的引用
        + 单一值 (e.g. intN/intptr [114514])
    + `flags`:值的集合
        + 一个flags描述的引用加上强调的类型(e.g. flags[mode_desc, int32])
    + `array`:一个可变/固定长度的数组
        + 元素的type加上可选的大小(e.g. array[intN, 114514]或者一个范围array[intN, 5:10])
    + `ptr/ptr64`:对象的指针
        + 方向(in/out/inout) (e.g. ptr/ptr64 [in]),无论目标指针大小为多少,ptr64的类型均为8字节
    + `string`: 以0结尾的缓冲区
        + 引号中的字符串值(e.g. string ["foo"] 或者使用16进制文字的 string [`deadbeef`])
        + string flags的引用,后面可以随意跟一个缓冲区大小
    + `stringnoz`:一个不以0为结尾的内存缓冲区
        + 引号中的字符串值(e.g. string ["foo"] 或者使用16进制文字的 string [`deadbeef`])
        + 一个对于string flags的引用
    + `glob`:匹配目标文件
        + 字符串正则表达式(e.g. glob ["/sys/**/*"])
        + 包含排除的glo`b(e.g. glob ["/sys/**/*:-/sys/power/state"])
    + `fmt`:一个整形字符串的引用
        + 格式化字符串("dec", "hex", "oct"其中之一)和值(int,flags, const或者是proc)
    + `len`: 字段长度
        + 参数名(e.g. len[argname])
    + `bytesize`: 类似于`len`,但总是以字节为单位表示大小
        + 参数名
    + `bitsize`: 类似于`len`,但总是以比特为单位表示大小
        + 参数名
    + `offsetof`: 父结构体中某个字段的偏移
        + 字段
    + `vma/vma64`: page集合的指针,~~使用mmap/munmap/mremap/madvise作为输入~~
        + page数量(e.g. vma[7])
        + pages范围(e.g. vma[2-4])
    + `proc`: 代表每个进程的整形变量
    + `compressed_image`: zlib-compressed 磁盘镜像
    + `text`: 特殊类型的机器码
        + 代码类型(e.g. x86_real, x86_16, x86_64, arm64)
    + `void`: 静态大小为0,不能作为系统调用参数

在`struct/unions/pointers`中使用时,`flags/len/`也具有后缀基础类型类型选项

标识位的集合描述为`flagname = const ["," const]*` 
如果对于字符串标志`flagname = "\"" literal "\"" ["," "\"" literal "\""]*`

### 1.Ints
其中`int8,int16, int32, int64`表示相应大小的整数,而`intptr`代表指针大小的整数,而如果在后面附加`be`后缀(e.g. int6be),这样整数将变为大端字节序列,这样我们使用一个官方给的例子来解说
```syzlang
example_struct {
	f0	int8			#随机的1字节
	f1	const[0x42, int16be]	# 值为0x4200的整形常量(大端序)	
    f2	int32[0:100]		# 0到100范围内的四字节的随机值
	f3	int32[1:10, 2]		# {1, 3, 5, 7, 9}范围内的随机数
	f4	int64:20		# 随机的20位比特字段
	f5	int8[10]		# 值为10的1字节大小整型常量
	f6	int32[flagname]		# 来自于名为flagname的集合中随机的4字节整型变量
}
```

### 2.Structs


### 3.Resorces
这个资源表示从一个系统调用输出到另一个系统调用输入的值,例如说我们close系统调用所传递fd值是由open系统调用得出的,所以这里的fd指针就可以使用该资源描述,其中规定如下:
```syzlang
"resource" identifier "[" underlying_type "]" [ ":" const ("," const)* ]
```
其中各个字段有如下含义:
+ underlying_type: 是int8, int16, int32, int64, intptr其中之一或者是其他资源.
+ 可选的常量集: 表示资源特殊值,例如`0xffffffffffffffff(-1)`表示"no fd", 或`AT_FDCWD`表示当前目录,下面为例子:
```syzlang
resource fd[int32]: 0xffffffffffffffff, AT_FDCWD, 1000000
resource sock[fd]
resource sock_unix[sock]

socket(...) sock
accept(fd sock, ...) sock
listen(fd sock, backlog int32)
```

可以看到其中的Resource类似于定义一种类型,他可以作为后面字段的一个临时underlying_type



# Volume IV:syzkaller自行编写系统调用
我们在fuzz的过程中当然希望我们能进行一些DIY的过程,那么接下来我们就来学习如何添加一个自定义的系统调用
根据官方文档,我们如果仅仅只想仅仅fuzz本地描述的新系统调用,那么在我们的配置文件当中的`enable_syscalls`配置参数对于新系统调用十分有用,
例如:`ioctl`将会启用所有满足其要求的所有描述的ioctl系统调用,而`ioctl$UDMABUF_CREATE`将会仅启用特定的ioctl调用,`write$UHID_*`启用以该描述标识符开头的所有写入系统调用

首先我们可以定义一个类型,这个类型专门用来作为我们的文件描述符
```syzlang
resource tmp_fd[int64]
```

然后我们就写一个自己定义规则的orw(OPEN-READ-WRITE)流程的系统调用
```syzlang
include<linux/fs.h>
resource tmp_fd[int64]

open$pwh_proc(file ptr64[in, string["/dev/tty"]], flag flags[open_flag]) tmp_fd
read$pwh_proc(fd tmp_fd, buffer ptr64[in, array[int8]], count bytesize[buffer])
write$pwh_proc(fd tmp_fd, buffer ptr64[out, array[int8]], count bytesize[buffer])
close$pwh_proc(fd tmp_fd)

open_flag = O_CREAT, O_RDWR, O_WRONLY, O_APPEND, O_ASYNC, O_CLOEXEC, O_DIRECT, O_DIRECTORY, O_DYSNC, O_EXCL, O_LARGEFILE, O_NOATIME, O_PATH
```
然后将文件名命名为`*.txt`然后将其放置在`sys/linux/`目录下
我们下一步依照官方文档来讲就可以生成/更新`*.const`文件了
这里官方给出的步骤为

```
make extract TARGETOS=linux SOURCEDIR=$KSRC
make generate
make
```
其中`make extract`用来生成/更新`*.const`文件,`$KSRC`则用来指向被fuzz的内核目录

然后



# Reference
[系统调用描述](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md)
