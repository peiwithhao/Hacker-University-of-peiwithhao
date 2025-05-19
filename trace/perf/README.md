# 性能优化
本板块搜集下列性能问题

# top
用来提供对进程的监控,包括cpu占用，内存占用等等信息

# iostat 

```sh
iostat -xmdz 1 5
```
其中参数`-x`用来显示扩展的统计信息
`-m`代表以M字节作为单位
`-k`代表以K字节作为单位
`-d`代表指定精度
`-z`省略采样没有活动的设备输出
后面的数字参数：
1代表显示间隔为1s
5代表显示5次停止


# sar
用来显示内核的活动信息
```sh
sar -A # 显示所有信息
sar -r # 显示内存信息
sar -B # 显示内核页信息
sar -n DEV # 显示网络相关信息
```
注意他和iostat一样也属于sysstat工具包，支持后面的间隔+次数格式

# vmstat
用来显示内核虚拟地址的信息
```sh
vmstat -Sm 1
```

参数`-S`代表打印单位, 1000(k), 1024(K), 1000000(m), 1048576(M)


# pgrep
查找进程名对应的pid,可以搭配strace来监控系统调用
```sh
strace -p `pgrep zsh`
```

# uptime
查看目前启动时间，有多少个用户登陆， 系统负载的平均时间(1, 5, 15)
```sh
$ uptime
 16:26:53 up 1 day,  6:06,  1 user,  load average: 1.18, 1.40, 1.38
```

# ps 
查看当前进程信息
```sh
ps -ef f #查看所有进程
```

其中`-e`是查看所有进程
`-f`是全格式打印

# mpstat
提供进程相关的统计信息

```sh
mpstat -P ALL 1
```
`-P`代表查看cpu利用信息
# strace
监控进程系统调用
`-n`: 打印系统调用号
`-ttt`: 打印执行的时候的时间
`-T`: 打印执行某个系统调用所消耗的时间
```sh
strace -tttnT -p 1234
```


# tcpdump
dump网络流量
`-i`: 代表需要监控的接口
`-w`: 写入的文件

# pidstat
打印linux任务的统计信息
`-t`：打印线程信息
```sh
pidstat -t 1
pidstat -d 1
```

`-d`:打印IO统计信息

# lsof
列出打开的文件

# ss
调查内部socket的工具
`-i`: 打印内部TCP信息
`-m`: 打印socket的内存使用
`-p`: 查看使用socket的进程
`-t`: tcp信息
`-u`: udp信息

# perf
用于linux的性能分析工具
通常会使用`perf record`来进行分析生成perf文件
然后使用`perf report`来查看该perf文件
