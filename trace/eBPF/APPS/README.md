# Fault Injection
## SYSCALL
### 注入部分
所有系统调用利用`kretprobe/__x64_sys_**`来进行hook, 使用`bpf_override_return`修改返回值
> [!NOTE]
> kretprobe实际上是一种kprobe,在触发kprobe之后寻找ret地址进行插桩

定义bpfmap记录比例

```c
#define OVERRIDE_RETURN(name)   \
    struct {\
        __uint(type, BPF_MAP_TYPE_ARRAY);\
        __type(key, u32);\
        __type(value, u32); \
        __uint(max_entries, 2);  \
    } fault_ratio_##name SEC(".maps"); \
    SEC("kretprobe/__x64_sys_"#name)   \
    int BPF_KRETPROBE(handle_exit_##name, long ret){ \
        int key = 0;    \
        u32 *filter_pid = bpf_map_lookup_elem(&filter, &key); \
        u64 pid_tgid = bpf_get_current_pid_tgid(); \
        if (filter_pid && *filter_pid != 0 && (*filter_pid != (pid_tgid >> 32))) \
            return 0;   \
        u32 *fault_ratio = bpf_map_lookup_elem(&fault_ratio_##name, &key); \
        u32 random = bpf_get_prandom_u32(); \
        if(random % 100 < *fault_ratio){    \
            bpf_override_return(ctx, -1);   \
        }                                   \
        return 0;                   \
    }

        /* bpf_override_return(ctx, -1); \ */
OVERRIDE_RETURN(openat);
OVERRIDE_RETURN(openat2);
OVERRIDE_RETURN(read);
OVERRIDE_RETURN(write);
```

这里的故障注入比例由用户态eBPF程序使用libbpf库来实现

```c
int main(int argc, char **argv)
{
    struct fault_injector_bpf *skel;
    int err, filter_pid = atoi(argv[1]);
    skel = fault_injector_bpf__open_and_load();
    if(!skel){
        fprintf(stderr, "failed to open/load skeleton\n");
        return 1;
    }
    int fault_ratio = 0;
    bpf_map_update_elem(bpf_map__fd(skel->maps.filter), &(uint32_t){0}, &filter_pid, BPF_ANY);
    bpf_map_update_elem(bpf_map__fd(skel->maps.fault_ratio_openat), &(uint32_t){0}, &fault_ratio, BPF_ANY);
    bpf_map_update_elem(bpf_map__fd(skel->maps.fault_ratio_openat2), &(uint32_t){0}, &fault_ratio, BPF_ANY);
    bpf_map_update_elem(bpf_map__fd(skel->maps.fault_ratio_read), &(uint32_t){0}, &fault_ratio, BPF_ANY);
    bpf_map_update_elem(bpf_map__fd(skel->maps.fault_ratio_write), &(uint32_t){0}, &fault_ratio, BPF_ANY);

    err = fault_injector_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach\n");
        goto cleanup;
    }

    getchar();

cleanup:
    fault_injector_bpf__destroy(skel);
    return 0;
}
```

### 效果
30%的故障率
注入前
```sh
peiwithhao@peiwithhao-Standard-PC-Q35-ICH9-2009:~/libbpf-bootstrap$ kubectl get pods -A
NAMESPACE            NAME                                         READY   STATUS    RESTARTS      AGE
kube-system          coredns-66bc5c9577-7m8fr                     1/1     Running   3 (14h ago)   3d20h
kube-system          coredns-66bc5c9577-tkmbq                     1/1     Running   5 (12h ago)   3d20h
kube-system          etcd-kind-control-plane                      1/1     Running   0             3d20h
kube-system          kindnet-ncwt9                                1/1     Running   5 (12h ago)   3d20h
kube-system          kube-apiserver-kind-control-plane            1/1     Running   2 (22m ago)   3d20h
kube-system          kube-controller-manager-kind-control-plane   1/1     Running   0             3d20h
kube-system          kube-proxy-7pxvl                             1/1     Running   6 (12h ago)   3d20h
kube-system          kube-scheduler-kind-control-plane            1/1     Running   0             3d20h
local-path-storage   local-path-provisioner-7b8c8ddbd6-wnvfl      1/1     Running   7 (13h ago)   3d20h
```
故障注入后
```sh
peiwithhao@peiwithhao-Standard-PC-Q35-ICH9-2009:~/libbpf-bootstrap$ kubectl get pods -A
NAMESPACE            NAME                                         READY   STATUS    RESTARTS      AGE
kube-system          coredns-66bc5c9577-7m8fr                     1/1     Running   3 (14h ago)   3d20h
kube-system          coredns-66bc5c9577-tkmbq                     1/1     Running   5 (12h ago)   3d20h
kube-system          etcd-kind-control-plane                      0/1     Running   0             3d20h
kube-system          kindnet-ncwt9                                1/1     Running   5 (12h ago)   3d20h
kube-system          kube-apiserver-kind-control-plane            0/1     Running   2 (24m ago)   3d20h
kube-system          kube-controller-manager-kind-control-plane   0/1     Running   0             3d20h
kube-system          kube-proxy-7pxvl                             1/1     Running   6 (12h ago)   3d20h
kube-system          kube-scheduler-kind-control-plane            0/1     Running   0             3d20h
local-path-storage   local-path-provisioner-7b8c8ddbd6-wnvfl      1/1     Running   7 (13h ago)   3d20h
```
可以通过影响系统调用导致几个关键pod失联

### 注入参数

比例可以通过监控系统调用错误比例进行

```c

struct syscall_start {
    u32 syscall_id;
    u64 ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct syscall_key);
    __type(value, struct syscall_val);
    __uint(max_entries, 1024);
} syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);              // pid_tgid
    __type(value, struct syscall_start);            // enter timestamp
    __uint(max_entries, 4096);
} start SEC(".maps");

// 可加过滤参数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 2); // 0: filter_pid, 1: filter_tid
} filter SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 key = 0;
    struct syscall_start sys_start = {};
    u32 *filter_pid = bpf_map_lookup_elem(&filter, &key);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (filter_pid && *filter_pid != 0 && (*filter_pid != (pid_tgid >> 32)))
        return 0;
    u64 ts = bpf_ktime_get_ns();
    sys_start.ts = ts;
    sys_start.syscall_id = ctx->id;
    bpf_map_update_elem(&start, &pid_tgid, &sys_start, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 key = 0;
    u32 *filter_pid = bpf_map_lookup_elem(&filter, &key);
    if (filter_pid && *filter_pid != 0 && (*filter_pid != (pid_tgid >> 32)))
        return 0;

    struct syscall_start *sys_start = bpf_map_lookup_elem(&start, &pid_tgid);
    if(!sys_start){
        return 0;
    }
    struct syscall_key skey = {};
    skey.err = ctx->ret;
    skey.id = sys_start->syscall_id;

    struct syscall_val zero = {};
    struct syscall_val *val = bpf_map_lookup_elem(&syscalls, &skey);
    if (!val) {
        zero.count = 1;
        /* u64 *ts = bpf_map_lookup_elem(&start, &pid_tgid); */
        u64 ts = sys_start->ts;
        zero.total_ns = bpf_ktime_get_ns() - ts;
        bpf_map_update_elem(&syscalls, &skey, &zero, BPF_ANY);
    } else {
        val->count += 1;
        u64 ts = sys_start->ts;
        val->total_ns += (bpf_ktime_get_ns() - ts);
        bpf_map_update_elem(&syscalls, &skey, val, BPF_ANY);
    }
    bpf_map_delete_elem(&start, &pid_tgid);
    return 0;
}
```

同样使用libbpf用户态程序进行监控，这里统计信息用到了uthash库
统计内容如下

```sh
syscall_id: 0
ERRNO      COUNT      RATIO      AVG_LATENCY(us)
0          513        0.747813   2.492070       
11         173        0.252187   0.772671       
syscall_id: 1
ERRNO      COUNT      RATIO      AVG_LATENCY(us)
0          465        1.000000   11.990102      
syscall_id: 15
ERRNO      COUNT      RATIO      AVG_LATENCY(us)
0          7          0.636364   1.600857       
4          4          0.363636   1.788000       
syscall_id: 233
ERRNO      COUNT      RATIO      AVG_LATENCY(us)
0          10         1.000000   2.953600       
syscall_id: 202
ERRNO      COUNT      RATIO      AVG_LATENCY(us)
0          1789       0.848672   10291.961914   
11         5          0.002372   0.778000       
110        314        0.148956   10273.125977   
syscall_id: 51
ERRNO      COUNT      RATIO      AVG_LATENCY(us)
0          5          1.000000   0.710200      
```



## Network
### 监控部分

面临的问题：
    1. 仅仅监控集群的API
    2. 如何区分集群和非集群的流量

首先问题1的解决办法是通过宏观的kubernetes集群获知，因为kubernetes集群上所有组件均是通过`kube-apiserver`来进行通信，所以他作为一个通信中枢，最主要是监控该进程下所获取到的API请求信息
因此这里将hook目标或目的是kube-apiserver的默认端口号6443
问题2的解决办法是使用`BPF_PROG_TYPE_CGROUP_SKB`,这样就可以通过绑定cgroup来监控该cgroup的所有流量从而不对其他cgroup进行影响

实验部分是对于出栈流量进行解析
```c
SEC("cgroup_skb/egress")
int apiserver_monitor(struct __sk_buff *skb) {
    struct iphdr iph;
    struct tcphdr tcph;
    struct net_event *e;
    __u32 tcp_offset;

    // 1. 加载 IP 头
    if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0) {
        return 1;  // 允许流量通过，跳过无效包
    }
    // 验证 IPv4 和协议
    if (iph.version != 4 || iph.ihl < 5 || iph.protocol != IPPROTO_TCP) {
        return 1;
    }
    // 跳过分片包（非第一个分片）
    __u16 frag_off = bpf_ntohs(iph.frag_off);
    if ((frag_off & IP_MF) || (frag_off & 0x1FFF)) {
        bpf_printk("fraging :(");
        return 1;  // 有后续分片或偏移非零，跳过
    }
    // 2. 计算 TCP 头偏移并加载
    tcp_offset = iph.ihl * 4;
    if (bpf_skb_load_bytes(skb, tcp_offset, &tcph, sizeof(tcph)) < 0) {
        return 1;
    }
    // 3. 过滤 API Server 流量（出站：sport ==Federation
    __u16 sport = bpf_ntohs(tcph.source);
    __u16 dport = bpf_ntohs(tcph.dest);
    if (sport != APISERVER_PORT && dport != APISERVER_PORT) {
        return 1;  // 非 API Server 流量，跳过
    }
    // 4. 分配 ringbuf 空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 1;  // ringbuf 分配失败，跳过
    }
    // 5. 填充事件结构体
    e->is_ingress = 0;  // egress 流量
    /* e->pid = bpf_get_current_pid_tgid() >> 32; */
    /* bpf_get_current_comm(&e->comm, sizeof(e->comm)); */
    e->saddr = iph.saddr;  // 网络字节序
    e->daddr = iph.daddr;
    e->sport = sport;
    e->dport = dport;
    e->len = skb->len;
    // 6. 提交事件并允许流量
    bpf_ringbuf_submit(e, 0);
    return 1;  // 允许流量通过
}
```

### 注入部分
直接将返回值设置为0即表示丢弃流量包，后续可以采取延迟等操作

## cgroup文件资源部分


# 参考
[https://troydhanson.github.io/uthash/userguide.html](https://troydhanson.github.io/uthash/userguide.html)
[https://github.com/libbpf/libbpf?tab=readme-ov-file](https://github.com/libbpf/libbpf?tab=readme-ov-file)
