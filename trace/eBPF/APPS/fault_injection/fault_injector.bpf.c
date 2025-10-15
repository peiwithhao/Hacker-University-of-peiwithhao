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
        if (fault_ratio == NULL ) { \
            return 0;       \
        }\
        u32 random = bpf_get_prandom_u32(); \
        if(random % 100 < *fault_ratio){    \
            bpf_override_return(ctx, -1);   \
        }                                   \
        return 0;                   \
    }

OVERRIDE_RETURN(openat);
OVERRIDE_RETURN(openat2);
OVERRIDE_RETURN(read);
OVERRIDE_RETURN(write);

