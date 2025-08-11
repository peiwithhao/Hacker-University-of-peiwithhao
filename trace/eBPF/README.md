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

# trace point

其中挂载点可以到`/sys/kernel/debug/tracing/available_events`中查询到

# libbpf-bootstrap讲解
讲解框架
## eBPF程序端
首先这里是注册libpf日志打印文件
```c

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}


int main(int argc, char **argv)
{
    ....
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
    ...
}
```
注册完打印函数，此时将会注册键盘传递信号的处理程序
```c
static void sig_handler(int sig)
{
	exiting = true;
}
int main(int argc, char **argv)
{
    ....
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
    ...
}
```
然后使用生成的`<app_name>_bpf__open()`函数，这个函数位于`OUTPUT/<app_name>_skel.h`当中,

```c
static inline struct bootstrap_bpf *
bootstrap_bpf__open(void)
{
	return bootstrap_bpf__open_opts(NULL);
}

static inline struct bootstrap_bpf *
bootstrap_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct bootstrap_bpf *obj;
	int err;
    /* alloc the struct bootstrap_bpf */

	obj = (struct bootstrap_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = bootstrap_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	bootstrap_bpf__destroy(obj);
	errno = -err;
	return NULL;
}
```
实际上就是隐藏了一系列后端的配置，主要的盲目地就是加载和验证BPF用户端
然后后面我们需要加载BPF程序，调用`<app_name>_bpf__load()`,同样这个函数位于`OUTPUT/<app_name>_skel.h`,然后将其绑定到tracepoint上面
```c
	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
```
之后由于用户需要与内核进行通信，因此这里建立环形缓冲区来轮询
```c
...
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
...
```

这里的环形缓冲区注册了一个绑定函数`handle_event`,
```c
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->exit_event) {
		printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "EXIT", e->comm, e->pid, e->ppid,
		       e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else {
		printf("%-8s %-5s %-16s %-7d %-7d %s\n", ts, "EXEC", e->comm, e->pid, e->ppid,
		       e->filename);
	}

	return 0;
}
```
而这个`struct event`是我们自己在`<app_name>.h`当中定义的

最后就是不断轮询
```c

...
	printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID",
	       "FILENAME/EXIT CODE");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
...
```
当然最后别忘了释放环形缓冲区和销毁在内核中的eBPF程序
```c
cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
```
## eBPF内核端
他的名字应该为`<app_name>.bpf.c`
首先是定义`eBPF_maps`的内容
```c
//bpf_helpers.h
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]
#define __ulong(name, val) enum { ___bpf_concat(__unique_value, __COUNTER__) = val } name

//bootstrap.bpf.c
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

```
从上述内容可以看到第一个示例maps是定义了如下几种元素
```c
int (*type)[BPF_MAP_TYPE_HASH];
int (*max_entries)[8192];
typeof(pid_t) *key;
typeof(u64) *value;
```
1. 符号名为type,max_entries的int类型数组
2. 符号名为key,指向pid_t类型
3. 符号名为value, 指向u64类型

依次类推下面的数据结构也是类似
所以这里是定义了两种数据结构，`exec_start`用来存储进程pid和与其相关的hash值等变量，而`rb`则用来存放ringbuffer,里面包含一些数据信息
`SEC(".maps")`表示这两个数据结构存放在ELF文件的`.maps`节

下面就是对不同的tracepoint运行的处理函数
```c
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
```

关于这里SEC宏可以从[内核文档](https://docs.kernel.org/bpf/libbpf/program_types.html)中获取

# ebpf helper
获取方式有两种: 
1. 通过`man bpf_helpers`获取欧
2. 通过`bpftool feature probe`

# 参考


[https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACING/](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACING/)
[https://docs.kernel.org/bpf/libbpf/program_types.html](https://docs.kernel.org/bpf/libbpf/program_types.html)

