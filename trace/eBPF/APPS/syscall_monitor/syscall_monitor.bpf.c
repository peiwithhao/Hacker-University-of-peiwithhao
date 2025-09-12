#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_monitor.h"
char LICENSE[] SEC("license") = "GPL";

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
    /* skey.id = ctx->id; */
    /* if (ctx->id < 0){ */
    /*     return 0; */
    /* } */
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
