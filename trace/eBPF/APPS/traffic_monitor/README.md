# TCP头部字段信息

在btf中tcp sock的结构体如下：
```c
struct bpf_tcp_sock {
        __u32 snd_cwnd;
        __u32 srtt_us;
        __u32 rtt_min;
        __u32 snd_ssthresh;
        __u32 rcv_nxt;
        __u32 snd_nxt;
        __u32 snd_una;
        __u32 mss_cache;
        __u32 ecn_flags;
        __u32 rate_delivered;
        __u32 rate_interval_us;
        __u32 packets_out;
        __u32 retrans_out;
        __u32 total_retrans;
        __u32 segs_in;
        __u32 data_segs_in;
        __u32 segs_out;
        __u32 data_segs_out;
        __u32 lost_out;
        __u32 sacked_out;
        __u64 bytes_received;
        __u64 bytes_acked;
        __u32 dsack_dups;
        __u32 delivered;
        __u32 delivered_ce;
        __u32 icsk_retransmits;
};
```
可以通过`bpf_tcp_scok(sk)`这个帮助函数获取,这里的sk则是通过以下链条获取
```
struct __sk_buff *skb
    sk = skb->sk
        sk = bpf_sk_fullsock(sk)
```
