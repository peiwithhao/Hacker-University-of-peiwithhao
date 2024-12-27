/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
//#include <linux/bpf.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "minimal_legacy.h"

#define MAX_ARGS 6
typedef int pid_t;
unsigned long long dev;
unsigned long long ino;



char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Create an array with 1 entry instead of a global variable
 * which does not work with older kernels */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, pid_t);
} my_pid_map SEC(".maps");

// 定义一个输出映射，用于将系统调用参数传递给用户空间
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
	/* store the ns */
	struct bpf_pidns_info ns;
	unsigned int index = 0;
	struct syscall_event *event;
	struct task_struct * cur;
	bpf_get_ns_current_pid_tgid(dev, ino, &ns, sizeof(ns));
	//pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t *my_pid = bpf_map_lookup_elem(&my_pid_map, &index);

	bpf_printk("ns pid: %d \n", ns.pid);
 	if (!my_pid || *my_pid != ns.pid)
		return 1;
	cur = (struct task_struct *)bpf_get_current_task();
	event = bpf_ringbuf_reserve(&rb, sizeof(struct syscall_event), 0);
	if(!event)
		return 0;

	u64 flags = BPF_CORE_READ(cur, thread_info.flags);
	event->syscall_id = ctx->id;
	event->is_compat = (flags & 0x30000000) == 0x30000000;

	bpf_printk("thread_info.flags: 0x%lx\n", flags);

	for(int i = 0 ; i < MAX_ARGS ; i++){
		event->args[i] = BPF_CORE_READ(ctx, args[i]);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}



