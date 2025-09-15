#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>




char LICENSE[] SEC("license") = "GPL";
// 可加过滤参数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 2); // 0: filter_pid, 1: filter_tid
} filter SEC(".maps");

SEC("kretprobe/__x64_sys_openat")
int override_all(struct trace_event_raw_sys_exit *ctx)
{

    int key = 0;
    u32 *filter_pid = bpf_map_lookup_elem(&filter, &key);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (filter_pid && *filter_pid != 0 && (*filter_pid != (pid_tgid >> 32)))
        return 0;
    long ret = ctx->ret;
    u32 r = bpf_get_prandom_u32();
    if (r % 100 < 30) {
        bpf_override_return(ctx, -1);
    }
    /* bpf_printk("syscall=%d, original_ret=%ld", syscall_nr, ret); */
    return 0;
}

