eBPF所支持的追踪变量
libbpf是一个用来方便用户编写eBPF程序的库函数框架,因此里面提供了许多供我们使用的函数API,其中要找到eBPF所支持的追踪变量,我们可以直接寻找其中提供的`src/bpf_helper_defs.h`

下面以列表的形式表现

| Function Name                        | Object                   | explain                                                      |
| ------------------------------------ | ------------------------ | ------------------------------------------------------------ |
| bpf_get_smp_processor_id()           | SMP ID                   | 多处理器模式下返回当前进程所处的处理器ID                     |
| bpf_get_current_pid_tgid()           | pid/tgid                 | 回复一个64位结构体,里面包含pid和tgid                         |
| bpf_get_current_uid_gid()            | uid/gid                  | 返回一个64位结构体,里面包含uid和gid                          |
| bpf_get_current_comm()               | struct task_struct->comm | 返回当前进程的执行名称,包含路径                              |
| bpf_get_cgroup_classid()             | classid                  | 检索当前任务的分类                                           |
| bpf_get_route_realm()                | realm or route           | 返回与sk_buff相联系的逻辑分区和route路径                     |
| bpf_get_stackid()                    | stack id                 | 返回成功或者无效的stack id,这个stackid可以与其他stackid结合形成火焰图等形式,但是否能构造出函数调用图有待考察 |
| bpf_get_hash_recalc()                | hash of the packet       | 计算包packet的hash值并且返回                                 |
| bpf_get_current_task()               | struct task_struct       | 返回当前进程/任务的PCB指针                                   |
| bpf_get_numa_node_id()               | numa_id                  | 若是NUMA架构,则其返回当前socket包所使用的numa_id             |
| bpf_get_socket_cookie()              | socket cookie            | 如果存在cookie则返回,若不存在则新生成一个cookie返回          |
| bpf_get_socket_uid()                 | socket_uid               | 获取该socket拥有者的id                                       |
| bpf_get_ns_current_pid_tgid()        | pid tgid in ns           | 命名空间中的pid和tgid                                        |
| bpf_current_task_under_cgroup()      | context                  | 测试运行实例使用cgroupv1还是cgroupv2                         |
| bpf_get_current_cgroup_id()          | cgroup id                | 返回当前进程所处于的cgroup id                                |
| bpf_get_current_ancestor_cgroup_id() | id of cgroupv2           | 返回当前进程所处于的cgroup祖先的cgroup id                    |
| bpf_get_current_task_btf()           | (BTF \*)task_truct       | 返回指向当前进程task_struct的BTF类型的指针                   |
| bpf_task_pt_regs()                   | pt_regs                  | 获取当前进程的pt_regs                                        |
| bpf_kallsyms_lookup_name()           | symbol address           | 获取内核符号的地址                                           |
| bpf_get_stack()                      | stack                    | 返回用户或内核栈到bpf程序所提供的buffer中                    |
| bpf_get_task_stack()                 | stack                    | 返回用户或内核栈到bpf程序所提供的buffer中                    |
| bpf_get_func_arg()                   | args                     | 获取追踪进程的第n个参数                                      |
| bpf_get_func_ret()                   | ret                      | 获取追踪进程的返回值                                         |
| bpf_get_func_arg_cnt()               | args_cnt                 | 获取追踪进程的参数个数                                       |



