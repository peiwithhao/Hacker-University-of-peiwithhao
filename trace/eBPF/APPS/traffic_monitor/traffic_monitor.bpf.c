#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "traffic_monitor.bpf.h"




SEC("cgroup_skb/egress")
int traffic_monitor_handler(struct __sk_buff *skb){
    unsigned long long curtime;
    unsigned long long delta = 0;

    int new_credit;
    int len = skb->len;
    /* 记录流量包信息 */
    struct traffic_pkt_info pkti;
    /* 记录当前时间 */

    unsigned int queue_index = 0
    struct traffic_queue_stats *tqs = NULL;
    struct traffic_vqueue *tvq = NULL;

    bool drop_flag;

    /* 获取ebpf map存放的traffic_queue_stats */
    tqs = bpf_map_lookup_elem(&queue_stats, &queue_index);

    // 如果网络接口是lo,且允许环回地址网卡,则放行
    if (tqs != NULL && !tqs->loopback && skb->ifindex == 1) {
        return ALLOW_PKT;
    }
    // 填充流量包信息结构体
    traffic_get_pkt_info(skb, &pkti);
    // 获取当前cgroup的信息
    tvq = bpf_cgrp_storage_get(&queue_state, NULL, BPF_GET_LOCAL_F_CREATE);
    if (!tvq){
        return ALLOW_PKT;
    }else if (tvq->lasttime == 0){
        // init the traffic_vqueue, update the lasttime and credit, rate
        traffic_vqueue_init(tvq, 1024);
    }

    // calculate the delta time = current time - last time
    curtime = bpf_ktime_get_ns();
    delta = curtime - tvq->lasttime;
    credit = tvq->credit;

    // Replenish the credit
    if (delta > 0) {
        tvq->lasttime = curtime;
        new_credit = credit + CREDIT_PER_NS(delta, tvq->rate);
        if (new_credit > MAX_CREDIT) {
            credit = MAX_CREDIT;
        }else {
            credit = new_credit;
        }
    }
    // Exhaust the credit
    credit -= len;
    tvq->credit = credit;

    // check if we should update the rate
    if (tqs != NULL && (tqs->rate * 128) != tvq->rate) {
        tvq->rate = tqs->rate * 128;
        bpf_printk("Updating rate: %d (1sec:%llu bits)\n", 
                   (int)tvq->rate, 
                   CREDIT_PER_NS(1000000000, tvq->rate) * 8);
    }
    // set flags (drop, congestion, cwr)
    if(credit < -DROP_THRESH || (len > LARGE_PKT_THRESH && credit < -LARGE_PKT_DROP_THRESH)){
        drop_flag = true;

    }






    return ALLOW_PKT;
}

char _license[] SEC("license") = "GPL";
