#include "cgrp_file_type.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
/* extern int bpf_strstr(const char *s1__ign, const char *s2__ign) __ksym; */

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, u64);
  __uint(max_entries, 1024);
} pid_fd_map SEC(".maps");

// 可加过滤参数
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 2); // 0: filter_pid, 1: filter_tid
} filter SEC(".maps");

// haystack/needle：字符串指针
// haystack_size/needle_size：各自的最大长度（一般为 buffer 长度）
// 0 for success , 1 for failed
static __always_inline int bpf_strnstr(const char *haystack, int haystack_size,
                                       const char *needle, int needle_size) {
  /* static int bpf_strnstr(const char *haystack, int haystack_size, const char
   * *needle, int needle_size) { */
  int i, j;
  if (needle_size == 0 || !needle || !*needle)
    return 0; // 空needle认为包含

  // haystack必须足够长才能继续
  if (!haystack || haystack_size <= 0 || haystack_size < needle_size)
    return 1;

  // 外层循环：遍历haystack
  for (i = 0; i <= haystack_size - needle_size; i++) {
    int match = 0;
    /* bpf_printk("i : %d", i); */

    // 如果遇到haystack的结尾('\0')，提前返回
    /* if (haystack[i] == '\0') */
    /*     break; */
    // 内层循环：比较needle
    for (j = 0; j < needle_size - 1; j++) {
      // 越界或遇到haystack结尾就失败
      /* if (i + j >= haystack_size) */
      /*     break; */
      if (haystack[i + j] != needle[j]) {
        match = 1;

        break;
      }
    }
    /* bpf_printk("\tj : %d", j); */
    // 如果j==needle_size说明全部匹配
    if (match == 0)
      return 0;
  }

  return 1;
}

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1024);
  __uint(key_size, sizeof(u32));
  __array(values, u32(void *));
} filter_jump_table SEC(".maps");

SEC("fexit/do_sys_openat2")
int BPF_PROG(cgrp_ftype_filter_memory, int dfd, const char *filename,
             struct open_how *how, int ret) {
  char memory_current_substr[] = MEMORY_CURRENT;
  char memory_max_substr[] = MEMORY_MAX;
  char memory_swap_current_substr[] = MEMORY_SWAP_CURRENT;
  char memory_swap_max_substr[] = MEMORY_SWAP_MAX;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  u64 pid_fd_key = ((pid_tgid >> 32) << 32 | (u64)ret);
  u64 pid_fd_value = 0;

  char haystack[0x80] = {0};
  bpf_probe_read_user_str(haystack, sizeof(haystack), filename);

  if (!bpf_strnstr(haystack, sizeof(haystack), memory_current_substr,
                   sizeof(memory_current_substr))) {
    pid_fd_value = TYPE_MEMORY_CURRENT;
    /* bpf_printk("memory reading file, fd: %d, %s, ", ret, filename); */
  } else if (!bpf_strnstr(haystack, sizeof(haystack), memory_max_substr,
                          sizeof(memory_max_substr)))
    pid_fd_value = TYPE_MEMORY_MAX;
  else if (!bpf_strnstr(haystack, sizeof(haystack), memory_swap_current_substr,
                        sizeof(memory_swap_current_substr)))
    pid_fd_value = TYPE_MEMORY_SWAP_CURRENT;
  else if (!bpf_strnstr(haystack, sizeof(haystack), memory_swap_max_substr,
                        sizeof(memory_swap_max_substr)))
    pid_fd_value = TYPE_MEMORY_SWAP_MAX;
  else
    bpf_tail_call(ctx, &filter_jump_table, 1);

  if (pid_fd_value) {
    bpf_map_update_elem(&pid_fd_map, &pid_fd_key, &pid_fd_value, BPF_ANY);
  }
  return 0;
}

SEC("fexit/do_sys_openat2")
int BPF_PROG(cgrp_ftype_filter_cpu, int dfd, const char *filename,
             struct open_how *how, int ret) {
  char cpu_weight_substr[] = CPU_WEIGHT;
  char cpu_max_substr[] = CPU_MAX;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  u64 pid_fd_key = ((pid_tgid >> 32) << 32 | (u64)ret);
  u64 pid_fd_value = 0;

  char haystack[0x80] = {0};
  bpf_probe_read_user_str(haystack, sizeof(haystack), filename);

  if (!bpf_strnstr(haystack, sizeof(haystack), cpu_weight_substr,
                   sizeof(cpu_weight_substr)))
    pid_fd_value = TYPE_CPU_WEIGHT;
  else if (!bpf_strnstr(haystack, sizeof(haystack), cpu_max_substr,
                        sizeof(cpu_max_substr)))
    pid_fd_value = TYPE_CPU_MAX;
  else
    bpf_tail_call(ctx, &filter_jump_table, 2);

  if (pid_fd_value) {
    bpf_map_update_elem(&pid_fd_map, &pid_fd_key, &pid_fd_value, BPF_ANY);
  }
  return 0;
}

SEC("fexit/do_sys_openat2")
int BPF_PROG(cgrp_ftype_filter_rdma, int dfd, const char *filename,
             struct open_how *how, int ret) {
  char rdma_max_substr[] = RDMA_MAX;
  char rdma_current_substr[] = RDMA_CURRENT;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  u64 pid_fd_key = ((pid_tgid >> 32) << 32 | (u64)ret);
  u64 pid_fd_value = 0;

  char haystack[0x80] = {0};
  bpf_probe_read_user_str(haystack, sizeof(haystack), filename);

  if (!bpf_strnstr(haystack, sizeof(haystack), rdma_max_substr,
                   sizeof(rdma_max_substr)))
    pid_fd_value = TYPE_RDMA_MAX;
  else if (!bpf_strnstr(haystack, sizeof(haystack), rdma_current_substr,
                        sizeof(rdma_current_substr)))
    pid_fd_value = TYPE_RDMA_CURRENT;
  else
    bpf_tail_call(ctx, &filter_jump_table, 3);

  if (pid_fd_value) {
    bpf_map_update_elem(&pid_fd_map, &pid_fd_key, &pid_fd_value, BPF_ANY);
  }
  return 0;
}

SEC("fexit/do_sys_openat2")
int BPF_PROG(cgrp_ftype_filter_pids, int dfd, const char *filename,
             struct open_how *how, int ret) {
  char pids_max_substr[] = PIDS_MAX;
  char pids_current_substr[] = PIDS_CURRENT;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  u64 pid_fd_key = ((pid_tgid >> 32) << 32 | (u64)ret);
  u64 pid_fd_value = 0;

  char haystack[0x80] = {0};
  bpf_probe_read_user_str(haystack, sizeof(haystack), filename);

  if (!bpf_strnstr(haystack, sizeof(haystack), pids_max_substr,
                   sizeof(pids_max_substr)))
    pid_fd_value = TYPE_PIDS_MAX;
  else if (!bpf_strnstr(haystack, sizeof(haystack), pids_current_substr,
                        sizeof(pids_current_substr)))
    pid_fd_value = TYPE_PIDS_CURRENT;
  else
    bpf_tail_call(ctx, &filter_jump_table, 4);

  if (pid_fd_value) {
    bpf_map_update_elem(&pid_fd_map, &pid_fd_key, &pid_fd_value, BPF_ANY);
  }
  return 0;
}

SEC("fexit/do_sys_openat2")
int BPF_PROG(cgrp_ftype_filter_misc, int dfd, const char *filename,
             struct open_how *how, int ret) {
  char misc_current_substr[] = MISC_CURRENT;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  u64 pid_fd_key = ((pid_tgid >> 32) << 32 | (u64)ret);
  u64 pid_fd_value = 0;

  char haystack[0x80] = {0};
  bpf_probe_read_user_str(haystack, sizeof(haystack), filename);

  if (!bpf_strnstr(haystack, sizeof(haystack), misc_current_substr,
                   sizeof(misc_current_substr)))
    pid_fd_value = TYPE_MISC_CURRENT;

  if (pid_fd_value) {
    bpf_map_update_elem(&pid_fd_map, &pid_fd_key, &pid_fd_value, BPF_ANY);
  }
  return 0;
}

SEC("fexit/do_sys_openat2")
int BPF_PROG(cgrp_ftype_filter, int dfd, const char *filename,
             struct open_how *how, int ret) {
  u32 key = 0;
  u32 *filter_pid = bpf_map_lookup_elem(&filter, &key);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  if (filter_pid && *filter_pid != 0 && (*filter_pid != (pid_tgid >> 32))) {
    return 0;
  }

  u64 pid_fd_key = ((pid_tgid >> 32) << 32 | (u64)ret);
  if (ret < 0) {
    return 0;
  }

  // 1. 检查是否是cgroup文件系统
  int fd = ret;
  struct task_struct *task = bpf_get_current_task();
  struct file **fds = NULL;
  fds = BPF_CORE_READ(task, files, fdt, fd);
  struct file *file = NULL;
  bpf_probe_read(&file, sizeof(file), &fds[fd]);
  if (file) {
    unsigned long long s_magic = 0;
    s_magic = BPF_CORE_READ(file, f_path.dentry, d_sb, s_magic);
    if (s_magic == CGROUP_V2_MAGIC) {
      bpf_tail_call(ctx, &filter_jump_table, 0);
    }
  }

  return 0;
}

// 可进行上调/下调
static __always_inline long memory_current_hijack(const char *value, u32 size) {
  unsigned long result = 0;
  if (bpf_strtoul(value, size, 0, &result) < 0) {
    return 0;
  }
  return result;
}

SEC("fexit/ksys_read")
int BPF_PROG(cgrp_read_hijack, unsigned int fd, const char *buf, size_t count,
             ssize_t ret) {
  u32 key = 0;
  u32 *filter_pid = bpf_map_lookup_elem(&filter, &key);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  if (filter_pid && *filter_pid != 0 && (*filter_pid != (pid_tgid >> 32))) {
    return 0;
  }
  if (ret <= 0) {
    return 0;
  }

  u64 pid_fd_key = ((pid_tgid >> 32) << 32 | (u64)fd);
  u64 *pid_fd_value = bpf_map_lookup_elem(&pid_fd_map, &pid_fd_key);
  if (!pid_fd_value) {
    return 0;
  }
  char dst[0x100] = {0};
  unsigned long result = 0;
  bpf_probe_read_user(dst, sizeof(dst), buf);
  switch (*pid_fd_value) {
  case TYPE_MEMORY_MAX:
    break;
  case TYPE_MEMORY_CURRENT:
    result = memory_current_hijack(dst, sizeof(dst));
    bpf_printk("reading result:%s %ld", buf, result);
    /* bpf_printk("reading fd: %d [%ld, %s]",fd,  memory_current_hijack(dst,
     * sizeof(dst)), dst); */
    break;
  case TYPE_MEMORY_SWAP_CURRENT:
    break;
  case TYPE_MEMORY_SWAP_MAX:
    break;
  case TYPE_CPU_WEIGHT:
    break;
  case TYPE_CPU_MAX:
    break;
  case TYPE_RDMA_MAX:
    break;
  case TYPE_RDMA_CURRENT:
    break;
  case TYPE_MISC_CURRENT:
    break;
  case TYPE_PIDS_MAX:
    break;
  case TYPE_PIDS_CURRENT:
    break;
  default:
    break;
  }

  /* bpf_probe_write_user(buf, dst_buffer, 0x30); */
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int close_handler(struct trace_event_raw_sys_enter *ctx) {
  u32 key = 0;
  u32 *filter_pid = bpf_map_lookup_elem(&filter, &key);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  if (filter_pid && *filter_pid != 0 && (*filter_pid != (pid_tgid >> 32))) {
    return 0;
  }

  u64 pid_fd_key = ((pid_tgid >> 32) << 32 | (u64)(ctx->args[0]));
  u64 *pid_fd_value = bpf_map_lookup_elem(&pid_fd_map, &pid_fd_key);
  if (!pid_fd_value) {
    return 0;
  }

  if (bpf_map_delete_elem(&pid_fd_map, &pid_fd_key)) {
    bpf_printk("delete elem failed");
    return 0;
  }
  /* bpf_printk("closing fd: %d", ctx->args[0]); */
  return 0;
}
