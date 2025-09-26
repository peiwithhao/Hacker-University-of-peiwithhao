#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "traffic_monitor.bpf.h"

SEC("cgroup_skb/egress")
int traffic_monitor_handler(struct __sk_buff *skb){
    unsigned long long curtime;
    unsigned long long delta = 0;

    int credit;
    int new_credit;
    int len = skb->len;
    /* 记录流量包信息 */
    struct traffic_pkt_info pkti;
    /* 记录当前时间 */

    unsigned int queue_index = 0;
    struct traffic_queue_stats *tqs = NULL;
    struct traffic_vqueue *tvq = NULL;

    bool drop_flag = false;
    bool congestion_flag = false;
    bool cwr_flag = false;
    bool ecn_ce_flag = false;

    int rv = ALLOW_PKT;

    /* 获取ebpf map存放的traffic_queue_stats, 这里表示用户传递的流量信息 */
    tqs = bpf_map_lookup_elem(&queue_stats, &queue_index);
    if (tqs == NULL) {
        return ALLOW_PKT;
    }

    // 如果网络接口是lo,且允许环回地址网卡,则放行
    if (!tqs->loopback && skb->ifindex == 1) {
        return ALLOW_PKT;
    }

    // 填充流量包信息结构体
    traffic_get_pkt_info(skb, &pkti);
    struct task_struct *task = bpf_get_current_task_btf();
    // 获取当前cgroup的信息
    tvq = bpf_cgrp_storage_get(&cgrp_storage, task->cgroups->dfl_cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tvq){
        bpf_printk("NONE");
        return ALLOW_PKT;
    }else if (tvq->lasttime == 0){
        // init the traffic_vqueue, update the lasttime and credit, rate
        /* traffic_vqueue_init(tvq, 1024); */
        traffic_vqueue_init(tvq, 1);
    }

    // calculate the delta time = current time - last time
    // 自旋锁防止其他核心竞争cgroup storage
    curtime = bpf_ktime_get_ns();
    __s32 old_credit;
    bpf_spin_lock(&tvq->lock);
    delta = curtime - tvq->lasttime;
    // 获取当前cgroup的剩余credit
    credit = tvq->credit;

    // 如果delta < 0, 说明在我们期间有其他核心抢占了锁, 那么这里我们就不再更新lasttime, 直接消耗credit
    if (delta > 0) {
        tvq->lasttime = curtime;
        new_credit = credit + CREDIT_PER_NS(delta, tvq->rate);
        if (new_credit > MAX_CREDIT) {
            credit = MAX_CREDIT;
        }else {
            credit = new_credit;
        }
    }
    // 提前消耗当前包的信用值，如果后期决定丢弃该包还需要加回来
    credit -= len;
    tvq->credit = credit;
    bpf_spin_unlock(&tvq->lock);

    // check if we should update the rate
    // 由于tqs是配置队列，所以需要判断配置和当前rate是否一致，如果不一致则需要更新配置
    if (tqs != NULL && (tqs->rate * 128) != tvq->rate) {
        tvq->rate = tqs->rate * 128;
        bpf_printk("Updating rate: %d (1sec:%llu bits)\n", 
                   (int)tvq->rate, 
                   CREDIT_PER_NS(1000000000, tvq->rate) * 8);
    }
    // set flags (drop, congestion, cwr)
    // drop_flag: 说明需要立刻丢包
    // congestion_flag: 说明出现了拥塞
    // cwr_flag: 给TCP使用，通知TCP发送端这里发生了拥塞
    if(credit < -DROP_THRESH ||
       (len > LARGE_PKT_THRESH && credit < -LARGE_PKT_DROP_THRESH)){ //这里表示出现严重超额
        drop_flag = true; //选择立刻丢包
        //如果显示包开启支持ECN拥塞控制, 则设置congestion_flag通知对端
        if (pkti.ecn) { 
            congestion_flag = true;
        //如果不支持ECN拥塞控制但为TCP协议，则设置cwr_flag通知tcp发送端
        }else if (pkti.is_tcp) {
            cwr_flag = true;
        }
    }else if (credit < 0) {
        // 
        if (pkti.ecn || pkti.is_tcp) {
            if (credit < -MARK_THRESH) {
                congestion_flag = true;
            }else {
                congestion_flag = false;
            }
        }else {
            congestion_flag = true;
        }
    }

    //设置此位标志表示希望标记流量出现拥塞，从而实现拥塞控制
    if (congestion_flag) {
        //Set  ECN (Explicit Congestion Notification) field of IP header 
        //to CE (Congestion Encountered) if current value is ECT (ECN Capable Transport).
        //Otherwise, do nothing. Works with IPv6 and IPv4.
        if (bpf_skb_ecn_set_ce(skb)){
            ecn_ce_flag = true;
        } else {
            if (pkti.is_tcp) {
                unsigned int rand_num = bpf_get_prandom_u32();
                if (-credit >= MARK_THRESH + (rand_num % MARK_REGION_SIZE)){
                    cwr_flag = true;
                }
            }else if (len > LARGE_PKT_THRESH) {
                drop_flag = true;
            }
        }
    }

    if(tqs != NULL){
        if(tqs->no_cn)
            cwr_flag = false;
    }
    /* bpf_printk("updating..."); */
    traffic_update_stats(tqs, len, curtime, congestion_flag, drop_flag, cwr_flag, ecn_ce_flag, &pkti, credit);
    if (drop_flag) {
        __sync_add_and_fetch(&(tvq->credit), len);
        rv = DROP_PKT;
    }
    /* bpf_printk("tqs rate: %lu, credit: ", tvq->credit); */
    if (cwr_flag)
        rv |= 2;
    /* bpf_printk("len: %llu, return value : %d", len, rv); */
    return rv;
}

char _license[] SEC("license") = "GPL";
