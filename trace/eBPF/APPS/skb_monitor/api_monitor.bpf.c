#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* #define APISERVER_PORT 6443 */
#define APISERVER_PORT 6443
#define TASK_COMM_LEN 16
#define IP_MF 0x2000  // More Fragments 标志
#define IP_DF 0x4000  // Don't Fragment 标志

// 和之前一样的事件结构体
struct net_event {
    bool is_ingress;
    __u32 pid;
    __u64 len;
    char comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// Ring Buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


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

/* SEC("cgroup_skb/ingress") */
/* int _hbm_in_cg(struct __sk_buff *skb) */
/* { */
/*     return 1; */
/* } */



char _license[] SEC("license") = "GPL";



