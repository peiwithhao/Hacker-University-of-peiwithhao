#ifndef __TRAFFIC_MONITOR_H
#define __TRAFFIC_MONITOR_H

struct traffic_vqueue{
    struct bpf_spin_lock lock;
    __u64 lasttime;
    int credit;     /* bytes */
    __u32 rate;  /* In byte per NS << 20 */
};

struct traffic_queue_stats {
    unsigned long rate;
    unsigned long stats:1, loopback:1, no_cn:1;
    unsigned long long bytes_total;
    unsigned long long pkts_total;
    unsigned long long pkts_marked;
    unsigned long long bytes_marked;
    unsigned long long pkts_ecn_ce;
    unsigned long long pkts_dropped;
    unsigned long long bytes_dropped;
    unsigned long long sum_cwnd;
    unsigned long long sum_cwnd_cnt;
    unsigned long long sum_rtt;

    unsigned long long firstPacketTime;
    unsigned long long lastPacketTime;

    unsigned long long returnValCount[4];
    long long sum_credit;
};
#endif
