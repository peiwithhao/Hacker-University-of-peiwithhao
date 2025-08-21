README大部分分析使用源码了，这里主要分析他的使用
# cgroup 概述
cgroups主要提供下面四个功能:
+ Resource Limiting: 可以设定Memory使用上限， 其中包含FileSystem的Cache
+ Prioritization: 不同的cgroup可以拥有不同的CPU跟Disk I/O使用优先顺序
+ Accounting: 计算Group内的资源使用状况，用来当作计费的依据
+ Control: 冻结或者是重启一整个group的process

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



# 参考
[https://medium.com/starbugs/%E7%AC%AC%E4%B8%80%E5%8D%83%E9%9B%B6%E4%B8%80%E7%AF%87%E7%9A%84-cgroups-%E4%BB%8B%E7%B4%B9-a1c5005be88c](https://medium.com/starbugs/%E7%AC%AC%E4%B8%80%E5%8D%83%E9%9B%B6%E4%B8%80%E7%AF%87%E7%9A%84-cgroups-%E4%BB%8B%E7%B4%B9-a1c5005be88c) 

