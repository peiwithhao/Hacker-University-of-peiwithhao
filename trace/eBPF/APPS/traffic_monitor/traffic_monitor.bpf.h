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
/* #define INIT_CREDIT 10 */
#define MAX_CREDIT (100 * MAX_BYTES_PER_PACKET)

#define CREDIT_PER_NS(delta, rate) ((((u64)(delta)) * (rate)) >> 20)

// Thresh: for controll the traffic
#define MARK_THRESH (40 * MAX_BYTES_PER_PACKET)
#define DROP_THRESH (80 * 5 * MAX_BYTES_PER_PACKET)
#define LARGE_PKT_DROP_THRESH (DROP_THRESH - (15 * MAX_BYTES_PER_PACKET))
#define MARK_REGION_SIZE (LARGE_PKT_DROP_THRESH - MARK_THRESH)
#define LARGE_PKT_THRESH 120

#define BURST_SIZE_NS   100000  // 100us
#define MARK_THRESH_NS  50000   // 50us
#define DROP_THRESH_NS  500000   // 500us
                               


/* 用来指示当前cgroup最近访问时间以及速率 */
/* struct { */
/* 	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE); */
/*     __uint(map_flags, BPF_F_NO_PREALLOC); */
/* 	__uint(max_entries, 0); */
/* 	__type(key, int); */
/*     /1* __type(value, struct traffic_vqueue); *1/ */
/*     __type(value, long); */
/* } queue_state SEC(".maps"); */

struct {
        __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, int);
        __type(value, struct traffic_vqueue);
} cgrp_storage SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct traffic_queue_stats);
} queue_stats SEC(".maps");


struct traffic_pkt_info {
    int cwnd; //拥塞窗口大小
    int rtt;
    int packets_out;
    bool is_ip;
    bool is_tcp;
    short ecn; //标记是否支持ecn
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
static __always_inline void traffic_vqueue_init(struct traffic_vqueue *tvq, int rate){
    bpf_printk("Initializing queue_state, rate:%d\n", rate * 128);
    tvq->lasttime = bpf_ktime_get_ns();
    tvq->credit = (__s32)INIT_CREDIT;
    tvq->rate = rate * 128;
}

static __always_inline void traffic_vqueue_edit(struct traffic_vqueue *tvq, int rate) {
    unsigned long long curtime;
    curtime = bpf_ktime_get_ns();
    tvq->lasttime = curtime - BURST_SIZE_NS;
    tvq->credit = 0;
    tvq->rate = rate * 128;
} 

static __always_inline void traffic_update_stats(struct traffic_queue_stats *tqs, 
                                                 int len,
                                                 unsigned long long curtime,
                                                 bool congestion_flag, 
                                                 bool drop_flag,
                                                 bool cwr_flag,
                                                 bool ecn_ce_flag,
                                                 struct traffic_pkt_info *pkti,
                                                 int credit)
{
    int rv = ALLOW_PKT;
    if (tqs != NULL) {
        // barrier
        __sync_add_and_fetch(&(tqs->bytes_total), len);
        if (tqs->stats){
            if (tqs->firstPacketTime == 0)
                tqs->firstPacketTime = curtime;
            tqs->lastPacketTime = curtime;
            __sync_add_and_fetch(&(tqs->pkts_total), 1);
            if (congestion_flag) {
                __sync_add_and_fetch(&(tqs->pkts_marked), 1);
                __sync_add_and_fetch(&(tqs->bytes_marked), len);
            }
            if (drop_flag) {
                __sync_add_and_fetch(&(tqs->pkts_dropped), 1);
                __sync_add_and_fetch(&(tqs->bytes_dropped), len);
            }
            if (ecn_ce_flag) {
                __sync_add_and_fetch(&(tqs->pkts_ecn_ce), 1);
            }
            if (pkti->cwnd) {
                __sync_add_and_fetch(&(tqs->sum_cwnd), pkti->cwnd);
                __sync_add_and_fetch(&(tqs->sum_cwnd_cnt), 1);
            }
            if (pkti->rtt) {
                __sync_add_and_fetch(&(tqs->sum_rtt), pkti->rtt);
            }
            __sync_add_and_fetch(&(tqs->sum_credit), credit);
            if (drop_flag)
                rv = DROP_PKT;
            if (cwr_flag)
                rv |= 2;
            if (rv == DROP_PKT) {
                __sync_add_and_fetch(&(tqs->returnValCount[0]), 1);
            }else if (rv == ALLOW_PKT) {
                __sync_add_and_fetch(&(tqs->returnValCount[1]), 1);
            }else if (rv == 2) {
                __sync_add_and_fetch(&(tqs->returnValCount[2]), 1);
            }else if (rv == 3) {
                __sync_add_and_fetch(&(tqs->returnValCount[3]), 1);
            }
        }
    }
}

#endif
