#ifndef __TRAFFIC_MONITOR_BPF_H
#define __TRAFFIC_MONITOR_BPF_H
#include "vmlinux.h"
#include "traffic_monitor.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DROP_PKT    0
#define ALLOW_PKT   1



#define INITIAL_CREDIT_PACKETS 100
#define MAX_BYTES_PER_PACKET 1500

// Credit
#define INIT_CREDIT (INITIAL_CREDIT_PACKETS * MAX_BYTES_PER_PACKET)
#define MAX_CREDIT (100 * MAX_BYTES_PER_PACKET)

#define CREDIT_PER_NS(delta, rate) ((((u64)(delta)) * (rate)) >> 20)

// Thresh: for control the traffic
#define MARK_THRESH (40 * MAX_BYTES_PER_PACKET)
#define DROP_THRESH (80 * 5 * MAX_BYTES_PER_PACKET)
#define LARGE_PKT_DROP_THRESH (DROP_THRESH - (15 * MAX_BYTES_PER_PACKET))




/* 用来指示当前cgroup最近访问时间以及速率 */
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 0);
	__type(key, struct bpf_cgroup_storage_key);
    __type(value, struct traffic_vqueue);
} queue_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct traffic_queue_stats);
} queue_stats SEC(".maps");


struct traffic_pkt_info {
    int cwnd;
    int rtt;
    int packets_out;
    bool is_ip;
    bool is_tcp;
    short ecn; //显示拥塞
};

static int get_tcp_info(struct __sk_buff *skb, struct traffic_pkt_info *pkti){
    struct bpf_sock *sk;
    struct bpf_tcp_sock *tp;
    sk = skb->sk;
    if (sk) {
        /* This helper gets a struct bpf_sock pointer 
         * such that all the fields in this bpf_sock can be accessed. */
        sk = bpf_sk_fullsock(sk);
        if (sk) {
            if (sk->protocol == IPPROTO_TCP) {
                /* This helper gets a struct bpf_tcp_sock pointer 
                 * from a struct bpf_sock pointer. */
                tp = bpf_tcp_sock(sk);
                if (tp) {
                    pkti->cwnd = tp->snd_cwnd;
                    pkti->rtt = tp->srtt_us >> 3;
                    pkti->packets_out = tp->packets_out;
                    return 0;
                }
            }
        }
    }
    pkti->cwnd = 0;
    pkti->rtt = 0;
    pkti->packets_out = 0;
    return 1;
}

static void traffic_get_pkt_info(struct __sk_buff *skb, struct traffic_pkt_info *pkti){
    struct iphdr iph;
    struct ipv6hdr *ip6h;
    pkti->cwnd = 0;
    pkti->rtt = 0;
    /* 加载ip头部 */
    bpf_skb_load_bytes(skb, 0, &iph, 12);
    if (iph.version == 6) {
        ip6h = (struct ipv6hdr *)&iph;
        pkti->is_ip = true;
        /* ip6h 头部nexthdr表示下一层级的协议 */
        pkti->is_tcp = (ip6h->nexthdr == IPPROTO_TCP);
        pkti->ecn = (ip6h->flow_lbl[0] >> 4) & INET_ECN_MASK;
    }else if (iph.version == 4) {
        pkti->is_ip = true;
        pkti->is_tcp = (iph.protocol == IPPROTO_TCP);
        // Type of service
        pkti->ecn = iph.tos & INET_ECN_MASK;
    }else {
        pkti->is_ip = false;
        pkti->is_tcp = false;
        pkti->ecn = 0;
    }
    if (pkti->is_tcp)
        get_tcp_info(skb, pkti);
}
static void traffic_vqueue_init(struct traffic_vqueue *tvq, int rate){
    bpf_printk("Initializing queue_state, rate:%d\n", rate * 128);
    tvq->lasttime = bpf_ktime_get_ns();
    tvq->credit = INIT_CREDIT;
    tvq->rate = rate * 128;
}

#endif
