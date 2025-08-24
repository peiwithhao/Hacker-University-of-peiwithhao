<!--toc:start-->
- [cgroup 概述](#cgroup-概述)
- [cgroup使用](#cgroup使用)
- [cgroup v2](#cgroup-v2)
- [cgroup 核心文件接口](#cgroup-核心文件接口)
- [控制器](#控制器)
  - [cpu 接口文件](#cpu-接口文件)
  - [memory 接口文件](#memory-接口文件)
  - [IO接口文件](#io接口文件)
  - [PID接口文件](#pid接口文件)
  - [Cpuset接口文件](#cpuset接口文件)
  - [RDMA接口文件](#rdma接口文件)
- [参考](#参考)
<!--toc:end-->

README大部分分析使用源码了，这里主要分析他的使用
# cgroup 概述
cgroups主要提供下面四个功能:
+ Resource Limiting: 可以设定Memory使用上限， 其中包含FileSystem的Cache
+ Prioritization: 不同的cgroup可以拥有不同的CPU跟Disk I/O使用优先顺序
+ Accounting: 计算Group内的资源使用状况，用来当作计费的依据
+ Control: 冻结或者是重启一整个group的process

下面主要介绍的是v1
cgroups 主要由四个元素构成
1. Task: 运行于作业系统内的Process, 在cgroups内被称为task
2. Subsystem: 资源控制器， 一个Subsystem管理一种资源， 例如CPU或是Memory：
    + blkio: 限制task对于存储设备的读取, 例如Disk, SSD, USB等等
    + cpu: 通过scheduler安排cgroup内Task存取CPU资源
    + cpuacct: 自动产生能够cgroup内的Task使用CPU资源的报告
    + cpuset: 为cgroup内的Task分配单独的CPU核心和memory
    + devices: 控制cgroup中Task可以存取的设备
    + freezer: 暂停和恢复cgroup内的task
    + memory: 限制task可以使用的memory, 并自动产生报告
    + net\_cls: 对网络封包标记上ClassID, 进而让Linux Traffic Controller根据这些ClassID得知网络封包来自于哪一个cgroup中的task
    + net\_prio: 为每一个network interface提供动态设定网络流量优先权的方法
    + ns: 有关于namespace的subsystem
    + perf\_event: 用来辨别task属于哪一个cgroup,并且可以拿来做能效分析
3. cgroup: cgroups额定资源控制单位，是task与subsystem的关系连接，用来定义task资源的管理策略, 如果将一个task加入到cgroup内，那么该task必须遵守该cgroup中所定义的规范
4. hierarchy: 一群cgroup组成的树状结构， 每个节点都是一个cgroup


# cgroup使用
可以简单的使用mkdir、rmdir来创建和删除cgroup, 
cgroup v1 和 v2 的区别为:

cgroup v1 下的目录结构:
```zsh
root@peiwithhao-Standard-PC-Q35-ICH9-2009:/sys/fs/cgroup/memory/democgv1# ls -l
total 0
-rw-r--r-- 1 root root 0  8月 21 16:00 cgroup.clone_children
--w--w--w- 1 root root 0  8月 21 16:00 cgroup.event_control
-rw-r--r-- 1 root root 0  8月 21 16:00 cgroup.procs
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.failcnt
--w------- 1 root root 0  8月 21 16:00 memory.force_empty
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.kmem.failcnt
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.kmem.limit_in_bytes
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.kmem.max_usage_in_bytes
-r--r--r-- 1 root root 0  8月 21 16:00 memory.kmem.slabinfo
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.kmem.tcp.failcnt
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.kmem.tcp.limit_in_bytes
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.kmem.tcp.max_usage_in_bytes
-r--r--r-- 1 root root 0  8月 21 16:00 memory.kmem.tcp.usage_in_bytes
-r--r--r-- 1 root root 0  8月 21 16:00 memory.kmem.usage_in_bytes
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.limit_in_bytes
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.max_usage_in_bytes
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.memsw.failcnt
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.memsw.limit_in_bytes
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.memsw.max_usage_in_bytes
-r--r--r-- 1 root root 0  8月 21 16:00 memory.memsw.usage_in_bytes
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.move_charge_at_immigrate
-r--r--r-- 1 root root 0  8月 21 16:00 memory.numa_stat
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.oom_control
---------- 1 root root 0  8月 21 16:00 memory.pressure_level
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.soft_limit_in_bytes
-r--r--r-- 1 root root 0  8月 21 16:00 memory.stat
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.swappiness
-r--r--r-- 1 root root 0  8月 21 16:00 memory.usage_in_bytes
-rw-r--r-- 1 root root 0  8月 21 16:00 memory.use_hierarchy
-rw-r--r-- 1 root root 0  8月 21 16:00 notify_on_release
-rw-r--r-- 1 root root 0  8月 21 16:00 tasks
```    

cgroup v2 下的目录结构
```zsh
❯ ls -l
.r--r--r-- 0 root 2025-08-21 14:59  cgroup.controllers
.r--r--r-- 0 root 2025-08-21 14:59  cgroup.events
.rw-r--r-- 0 root 2025-08-21 14:59  cgroup.freeze
.-w------- 0 root 2025-08-21 14:59  cgroup.kill
.rw-r--r-- 0 root 2025-08-21 14:59  cgroup.max.depth
.rw-r--r-- 0 root 2025-08-21 14:59  cgroup.max.descendants
.rw-r--r-- 0 root 2025-08-21 14:59  cgroup.pressure
.rw-r--r-- 0 root 2025-08-21 14:59  cgroup.procs
.r--r--r-- 0 root 2025-08-21 14:59  cgroup.stat
.rw-r--r-- 0 root 2025-08-21 14:59  cgroup.subtree_control
.rw-r--r-- 0 root 2025-08-21 14:59  cgroup.threads
.rw-r--r-- 0 root 2025-08-21 14:59  cgroup.type
.rw-r--r-- 0 root 2025-08-21 14:59  cpu.idle
.rw-r--r-- 0 root 2025-08-21 14:59  cpu.max
.rw-r--r-- 0 root 2025-08-21 14:59  cpu.max.burst
.rw-r--r-- 0 root 2025-08-21 14:59  cpu.pressure
.r--r--r-- 0 root 2025-08-21 14:59  cpu.stat
.r--r--r-- 0 root 2025-08-21 14:59  cpu.stat.local
.rw-r--r-- 0 root 2025-08-21 14:59  cpu.uclamp.max
.rw-r--r-- 0 root 2025-08-21 14:59  cpu.uclamp.min
.rw-r--r-- 0 root 2025-08-21 14:59  cpu.weight
.rw-r--r-- 0 root 2025-08-21 14:59  cpu.weight.nice
.rw-r--r-- 0 root 2025-08-21 14:59  cpuset.cpus
.r--r--r-- 0 root 2025-08-21 14:59  cpuset.cpus.effective
.rw-r--r-- 0 root 2025-08-21 14:59  cpuset.cpus.exclusive
.r--r--r-- 0 root 2025-08-21 14:59  cpuset.cpus.exclusive.effective
.rw-r--r-- 0 root 2025-08-21 14:59  cpuset.cpus.partition
.rw-r--r-- 0 root 2025-08-21 14:59  cpuset.mems
.r--r--r-- 0 root 2025-08-21 14:59  cpuset.mems.effective
.rw-r--r-- 0 root 2025-08-21 14:59  io.bfq.weight
.rw-r--r-- 0 root 2025-08-21 14:59  io.latency
.rw-r--r-- 0 root 2025-08-21 14:59  io.max
.rw-r--r-- 0 root 2025-08-21 14:59  io.pressure
.rw-r--r-- 0 root 2025-08-21 14:59  io.prio.class
.r--r--r-- 0 root 2025-08-21 14:59  io.stat
.rw-r--r-- 0 root 2025-08-21 14:59  io.weight
.rw-r--r-- 0 root 2025-08-21 14:59  irq.pressure
.r--r--r-- 0 root 2025-08-21 14:59  memory.current
.r--r--r-- 0 root 2025-08-21 14:59  memory.events
.r--r--r-- 0 root 2025-08-21 14:59  memory.events.local
.rw-r--r-- 0 root 2025-08-21 14:59  memory.high
.rw-r--r-- 0 root 2025-08-21 14:59  memory.low
.rw-r--r-- 0 root 2025-08-21 14:59  memory.max
.rw-r--r-- 0 root 2025-08-21 14:59  memory.min
.r--r--r-- 0 root 2025-08-21 14:59  memory.numa_stat
.rw-r--r-- 0 root 2025-08-21 14:59  memory.oom.group
.rw-r--r-- 0 root 2025-08-21 14:59  memory.peak
.rw-r--r-- 0 root 2025-08-21 14:59  memory.pressure
.-w------- 0 root 2025-08-21 14:59  memory.reclaim
.r--r--r-- 0 root 2025-08-21 14:59  memory.stat
.r--r--r-- 0 root 2025-08-21 14:59  memory.swap.current
.r--r--r-- 0 root 2025-08-21 14:59  memory.swap.events
.rw-r--r-- 0 root 2025-08-21 14:59  memory.swap.high
.rw-r--r-- 0 root 2025-08-21 14:59  memory.swap.max
.rw-r--r-- 0 root 2025-08-21 14:59  memory.swap.peak
.r--r--r-- 0 root 2025-08-21 14:59  memory.zswap.current
.rw-r--r-- 0 root 2025-08-21 14:59  memory.zswap.max
.rw-r--r-- 0 root 2025-08-21 14:59  memory.zswap.writeback
.r--r--r-- 0 root 2025-08-21 14:59  pids.current
.r--r--r-- 0 root 2025-08-21 14:59  pids.events
.r--r--r-- 0 root 2025-08-21 14:59  pids.events.local
.rw-r--r-- 0 root 2025-08-21 14:59  pids.max
.r--r--r-- 0 root 2025-08-21 14:59  pids.peak
```

差别可以看到cgroup v1 需要在对应的subsystme下面创建子cgroup

但是v2创建的子cgroup内部已经有了多种subsystem

v2可以指定使用哪一些subsystem, 可以通过查看cgroup.controllers可以看到
```zsh
❯ cat cgroup.controllers
cpuset cpu io memory pids
```


# cgroup v2
他和v1的控制器有些许区别:
+ cpu: 继承v1的cpu和cpuacct
+ cpuset: 继承v1的cpuset
+ freezer: 继承v1的freezer
+ hugetlb: 继承v1的hugetlb
+ io: 继承v1的blkio
+ memory: 继承v1的memory
+ perf\_event: 类似v1的perf\_event
+ pids: 类似v1的pids
+ rdma: 类似v1的rdma

对于v1的`net_cls, net_prio`, v2并没有直接等价的控制器， 而是将其添加到了ebpf filter的hook点位中

+ devices: 不提供接口文件，通过ebpf(BPF_CGROUP_DEVICE)来提供控制

# cgroup 核心文件接口
对于一些子文件类似于`memory.current`内容的统计，我们可以通过查看`Documentation/admin-guide/`下面的文件查看
cgroup v1: `Documentation/admin-guide/cgroup-v1/*`
cgroup v2: `Documentation/admin-guide/cgroup-v2.rst`

+ cgroup.type: 存在于非root cgroup上，可以是下列值之一
    + `domain`: 正常有效的域cgroup
    + `domain threaded`: 作为线程子树根的线程域cgroup
    + `domain invalid`: 处于无效状态的cgroup
    + `threaded`: 线程cgrouo, 是线程子树的成员
+ cgroup.procs: 所有cgroup都存在
    + 读取时会列出属于该cgroup的所有进程的PID
+ cgroup.threads: 所有cgroup都存在
    + 读取时会列出属于该cgreoup的所有线程的TID
+ cgroup.controllers: 显示该cgroup中所有可用控制器的列表
+ cgroup.subtree_control: 在所有cgroup中，显示控制器列表，这些控制器可以控制从cgroup到其子组资源的分配
+ cgroup.events: 存在于非root cgroup上， 定义以下条目:
    + `populated`: 如果cgroup或其后代包含任何活动进程则为1, 否则为0
    + `frozen`: 如果cgroup被冻结则为1, 否则为0
+ cgroup.max.descendants: 默认为`max`, 表示最大后代cgroup数量, 如果大于将会创建新cgroup失败
+ cgroup.max.depth: 默认为`max`, 当前cgroup的最大下降深度, 如果大于将会创建子cgroup失败
+ cgroup.stat: 具有以下条目的只读文件:
    + `nr_descendants`: 后代cgroup数目
    + `nr_dying_descendants`: 死亡后裔数量
    + `nr_subsys_<cgroup_subsys>`: 当前cgroup中及之下的活动cgroup总数
    + `nr_dying_subsys_<cgroup_subsys>`: 当前cgroup中及之下的消亡cgroup总数

+ cgroup.freeze: 
    + 写1会冻结cgroup及其后代cgroup, 意味着所有所属进程都将停止, 该操作之后cgroup.events中的frozen将被更新为1, 并发出相应通知
+ cgroup.kill: 向文件写1会导致该cgroup和后代cgroup被终止，所有属于该cgroup树中的进程，都将通过SIGKILL信号被终止
+ cgroup.pressure: 向文件写入0将禁用cgroup PSI 核算(用来衡量和量化压力水平)。向文件写1将重新启用cgroup PSI核算, 写入1将重新启用PSI核算
+ irq.pressure: 中断压力

# 控制器
## cpu 接口文件
时间长度均为微秒
+ cpu.stat: 有下列数据, 这些数据涵盖cgroup中所有进程
    + `usage_usec`
    + `user_usec`
    + `system_usec`
    当控制器启用的时候还有下面五个:
    + `nr_periods`: 周期数
    + `nr_throttled`
    + `throttled_usec`
    + `nr_bursts`: 突发次数
    + `burst_usec`: 突发秒数
+ cpu.weight: cpu权重，存在于非root cgroup, 默认值为100,对于非空闲组(cpu.idle=0),  范围为\[1, 10000\], 如果是空闲组(cpu.idle=1),则权重为0
+ cpu.weight.nice: 存在于非root cgroup 默认值为0, nice范围为\[-20, 19\], 这里是cpu.weight的代替接口
+ cpu.max: 默认值为"max 100000", 格式为"$MAX $PERIOD", 表示该组在每个$PERIOD最多消费$MAX, max表示无限制
+ cpu.max.burst: 默认值为0, 爆发范围为\[0, $MAX\], 仅影响公平类调度程序下的进程
+ cpu.pressure: 显示CPU的压力信息
+ cpu.idle: 默认为0, 如果为1表示cgroup的调度策略变为`SCHED_IDLE`

## memory 接口文件
+ memory.current: 当前内存, 表示当前cgroup和其后代正在使用的内存总量
+ memory.min: 默认为0, 是一种硬内存保护(内存紧张也不能释放该范围内的内存)， 如果内存使用量在最小边界内， 则cgroup的内存在任何情况都不会被回收。 如果超出有效最小边界，则会按照比例回收页面
+ memory.low: 默认为0, 是一种软内存保护(内存紧张尽量保证别释放该范围内的内存), 如果内存使用量在有效的边界内, 则该cgroup的内存不会被回收。如果超过了有效低边界，则会根据超额部分按照比例回收内存
+ memory.high: 默认值为max, 内存使用限制， 如果某个cgroup的使用量超出上线则该cgroup的进程将受到限制
+ memory.max: 内存使用硬限制, 如果超出该值那么该cgroup会调用OOM killer
+ memory.reclaim: 写入内存大小， 触发内存回收
+ memory.peak: 内存峰值， 记录cgroup和后代的最大内存使用量
+ memory.oom.group: 默认为"0", 确定确定OOM程序是否应将cgroup视为不可分割的工作负载， 如果设置了此选项则属于该cgroup或其后代的所有任务将被一起终止或者根本不终止, 具有OOM保护(`oom_score_adj` 设置为-1000)的任务将被视为异常且永远不会被终止
+ memory.stat: 内存统计, 所有内存量以字节为单位
    + `anon`: 匿名映射中使用的内存量, 例如`brk(), sbrk()`和`mmap(MAP_ANONYMOUS)`
    + `file`: 用于缓存文件系统数据的内存量，包括tmpfs和共享内存
    + `kernel(npm)`: 内核内存总量, 包括内核栈、页表、cpu段、vmaloloc、slab以及其他内核内存用量
    + `kernel_stack`: 分配给内核堆栈的内存量
    + `pagetables`: 为页表分配的内存量
    + `sec_pagetables`: 为二级页表分配的内存量
    + `percpu(npm)`: 存储每个cpu内核数据结构的内存量
    + `sock(npn)`: 网络传输缓冲区使用的内存量
    + `vmalloc(npn)`: 用于vmalloc支持的内存量
    + `shmem`: 交换支持的缓存文件系统数据量，例如tmpfs, shm段， 共享匿名mmap()
    + `zswap`: zswap压缩后的应用程序内存量
    + `zswapped`: 换出到zswaped的应用程序内存量
    + `file_mapped`: 文件映射, 使用mmap()映射的缓存文件系统数据量
    + `file_dirty`: 已修改但尚未写回磁盘的缓存文件系统数据量
    + `file_writback`: 已修改且正在写回磁盘的缓存文件系统数据量
    + `swapcached`: 内存中缓存的交换空间大小
    + `anon_thp`: 透明大页面支持的匿名映射中使用的内存量
    + `shmem_thp`: 透明大页面支持的shm,包括tmpfs和共享内存, 共享匿名mmap()的数量
    + `inactive_anon, active_anon, inactive_file, active_file, unevicatable`: 
    + `slab_reclaimable`: slab中可能会被回收的部分，例如dentry和inode
    + `slab_unreclaimable`: 由于内存压力，slab中无法回收的部分
    + `slab(npn)`: 用于存储内核数据结构的内存量
    + `workingset_refault_anon`: 先前驱逐的匿名页面的重新故障次数
    + `workingset_refault_file`: 先前驱逐的文件页面的重新故障次数
    + `workingset_activate_anon`: 被重新故障并立即激活的匿名页面的数量
    + `workingset_activate_file`: 被重新故障并立即激活的文件页面的数量
    + `workingset_restore_anon`: 在被回收之前被检测为活动工作集的已恢复匿名页面的数量
    + `workingset_restore_file`: 在被回收之前被检测为活动工作集的已恢复文件页面的数量
    + `workingset_nodereclaim`: 影子节点被回收的次数
    + `pswpin(npn)`: 交换到内存的页面数
    + `pswpout(npn)`: 内存中已换出的页面数
    + `pgscan(npn)`: 扫描页面数量(在非活动LRU列表中)
    + `pgsteal(npn)`: 回收页面数量
    + `pgscan_kswapd(npn`: kswapd扫描的页面数量
    + `pgscan_direct(npn)`: 直接扫描的页面数量
    + `pgscan_khugepaged(npn)`: khugepaged扫描的页面数量
    + `pgscan_proactive(npn)`: 主动扫描的页面数量
    + `pgsteal_kswapd(npn)`: kswapd回收的页面数量
    + `pgsteal_direct(npn)`: 直接回收的页面数量
    + `pgsteal_khugepaged(npn)`: khugepaged回收的页面数量
    + `pgsteal_proactive(npn)`: 主动回收的页面数量
    + `pgfault(npn)`: 发生的页面错误计数
    + `pgmajfault(npn)`: 发生的重大页面错误计数
    + `pgactivate(npn)`: 移动到活动LRU列表的页面数量
    + `pgdeactivate(npn)`: 移到非活动LRU列表的页面数量
    + `pglazyfree(npn)`: 内存压力下推迟释放的页面数量
    + `pglazyfreed(npn)`: 回收的lazyfree页面数量
    + `swpin_zero`: 换入内存并填充为0的页面数量
    + `swpout_zero`: 由于检测到内容为0而跳过I/O的换出零填充页面的数量
    + `zswpin`: 从zswapd移入内存的页面数量
    + `zswpout`: 从内存移出到zswap的页面数量
    + `zswpwb`: 从zswap写入swap的页面数量
    + `thp_fault_alloc(npn)`: 为结局页面错误而分配的透明大页数量
    + `thp_collapse_alloc(npn)`: 为折叠现有的页面范围而分配的透明大页数量
    + `thp_swpout(npn)`: 无需拆分即可整体交换的透明大页面数量
    + `thp_swpout_fallback(npn)`: 交换前被拆分的透明大页数量
    + `numa_pages_migrated(npn)`: 通过NUMA平衡迁移的页面数量
    + `numa_pte_updates(npn)`: 通过NUMA平衡修改页表条目以在访问时产生NUMA提示错误的页面数量
    + `numa_hint_faults(npn)`: NUMA提示错误的数量
    + `pgdemote_kswapd`: 由kswapd降级的页面数量
    + `pgdemote_direct`: 直接降级的页面数量
    + `pgdemote_khugepaged`: 被khugepaged降级的页面数量
    + `pgdemote_proactive`: 主动降级的页面数量
    + `hugetlb`: hugetlb页面占用的内存量
+ memory.swap.current: 该cgroup及其后代当前正在使用的交换总量
+ memory.swap.high: 默认为max, 交换空间使用限制，如果超过此限制，则所有后续分配都将受到限制
+ memory.swap.peak: 记录的cgroup及其后代的最大交换使用情况
+ memory.swap.max: 交换空间使用的硬限制，如果答案到此限制，那么该cgroup的匿名内存将不会被换出
+ memory.swap.events: 存在下列条目
    + high: cgroup的交换使用量超过高阈值的次数
    + max: cgroup的交换使用将超出最大边界且交换分配失败的次数
    + fail: 由于系统范围内的交换空间不足或最大限制而导致交换分配失败
+ memory.zswap.current: zswap压缩后端后的内存总量
+ memory.zswap.max: zswap使用硬限制， 如果cgroup的zswap池达到此限制，他将拒绝现有条目故障恢复或写入磁盘之前接受任何存储
+ memory.zswap.writeback: 为0时所有交换设备的交换尝试均被禁用
+ memory.pressure: 显示内存的压力失速信息


## IO接口文件

+ io.stat: 行以$MAJ:$MIN为键, 定义了下列嵌套key
    |rbytes|Bytes read|
    |--|--|
    |wbytes|Bytes written|
    |rios|Number of read IOs|
    |wios|Number of write IOs|
    |dbytes|Bytes discarded|
    |dios|Number of discard IOs|
+ io.max: 基于BPS和IOPS的IO限制 
+ io.pressure: 显示IO的压力速失信息

## PID接口文件
+ pids.max: 进程数量硬性限制
+ pids.current: cgroup及其后代中当前的进程数量
+ pids.peak: cgroup及其后代中进程数量曾经达到的最大值

## Cpuset接口文件
+ cpuset.cpus: 列出此cgroup中任务所申请额定cpu资源
+ cpuset.cpus.effective: 列出了此cgroup的父cgroup实际授予的在线cpu, 该值将会受到cpu热插拔时间的影响
+ cpuset.mems: 此cgroup中人物所申请的内存节点
+ cpuset.mems.effective: 列出了此cgroup的父cgroup实际授予的在线内存节点
+ cpuset.cpus.exclusive: 列出所有允许用于创建新cpuset分区额定独占CPU
+ cpuset.cpus.exclusive.effective: 显示用于创建分区根的有效独占CPUset


## RDMA接口文件
+ rdma.max: 描述RDMA/IB 设备当前的资源限制
+ rdma.current: 描述当前资源使用情况的只读文件

## HugeTLB接口文件
+ hugetlb.<hugepagesize>.current: 显示"hugepagesize" hugetlb的当前使用情况
+ hugetlb.<hugepagesize>.max: 使用量的硬限制
+ hugetlb.<hugepagesize>.events: 默认为max, 表示由于HugeTLB限制导致分配的次数
+ hugetlb.<hugepagesize>.events.local: 类似上部分
+ hugetlb.<hugepagesize>.numa_stat: 显示hugetlb页的numa信息

## Misc 杂项接口文件
+ misc.capacity: 显示平台上可用的各种标量资源及其数量
+ misc.current: 显示cgroup及其子组内资源的当前使用情况
+ misc.peak: 显示cgroup及其子cgroup的历史最大资源使用情况
+ misc.max: 允许最大使用cgroup的资源


# 参考
[https://medium.com/starbugs/%E7%AC%AC%E4%B8%80%E5%8D%83%E9%9B%B6%E4%B8%80%E7%AF%87%E7%9A%84-cgroups-%E4%BB%8B%E7%B4%B9-a1c5005be88c](https://medium.com/starbugs/%E7%AC%AC%E4%B8%80%E5%8D%83%E9%9B%B6%E4%B8%80%E7%AF%87%E7%9A%84-cgroups-%E4%BB%8B%E7%B4%B9-a1c5005be88c) 
[https://docs.kernel.org/admin-guide/cgroup-v2.html](https://docs.kernel.org/admin-guide/cgroup-v2.html)

