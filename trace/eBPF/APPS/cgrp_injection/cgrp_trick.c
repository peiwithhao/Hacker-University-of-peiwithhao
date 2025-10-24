#include "cgrp_trick.skel.h"
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "you run this prog with wrong arg num :(");
    return 1;
  }

  struct cgrp_trick_bpf *skel;
  skel = cgrp_trick_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "failed to open/load skeleton\n");
    return 1;
  }

  int err, interval = 5, filter_pid = atoi(argv[1]);

  // 1. 设置过滤PID, tid
  bpf_map_update_elem(bpf_map__fd(skel->maps.filter), &(uint32_t){0},
                      &filter_pid, BPF_ANY);
  // 2. 设置bpf tail call 跳转函数
  //  memory 文件过滤
  int prog_fd = bpf_program__fd(skel->progs.cgrp_ftype_filter_memory);
  bpf_map_update_elem(bpf_map__fd(skel->maps.filter_jump_table), &(uint32_t){0},
                      &prog_fd, BPF_ANY);
  // cpu 文件过滤
  prog_fd = bpf_program__fd(skel->progs.cgrp_ftype_filter_cpu);
  bpf_map_update_elem(bpf_map__fd(skel->maps.filter_jump_table), &(uint32_t){1},
                      &prog_fd, BPF_ANY);
  // rdma 文件过滤
  prog_fd = bpf_program__fd(skel->progs.cgrp_ftype_filter_rdma);
  bpf_map_update_elem(bpf_map__fd(skel->maps.filter_jump_table), &(uint32_t){2},
                      &prog_fd, BPF_ANY);
  // pids 文件过滤
  prog_fd = bpf_program__fd(skel->progs.cgrp_ftype_filter_pids);
  bpf_map_update_elem(bpf_map__fd(skel->maps.filter_jump_table), &(uint32_t){3},
                      &prog_fd, BPF_ANY);
  // misc 文件过滤
  prog_fd = bpf_program__fd(skel->progs.cgrp_ftype_filter_misc);
  bpf_map_update_elem(bpf_map__fd(skel->maps.filter_jump_table), &(uint32_t){4},
                      &prog_fd, BPF_ANY);

  /* err = cgrp_trick_bpf__attach(skel); */
  // NOTE: 这里注意因为需要使用bpf_tail_call
  // 所以这里并不会全部attach,而是选择部分attach 加载过滤文件主程序
  struct bpf_link *link = bpf_program__attach(skel->progs.cgrp_ftype_filter);
  if (link == NULL) {
    fprintf(stderr, "Error: bpf_program__attach failed\n");
    goto cleanup;
  }

  // 加载读取修改程序
  link = bpf_program__attach(skel->progs.cgrp_read_hijack);
  if (link == NULL) {
    fprintf(stderr, "Error: bpf_program__attach failed\n");
    goto cleanup;
  }

  // 加载关闭程序
  link = bpf_program__attach(skel->progs.close_handler);
  if (link == NULL) {
    fprintf(stderr, "Error: bpf_program__attach failed\n");
    goto cleanup;
  }

  while (1) {
    fprintf(stderr, ".");
    sleep(1);
  }

cleanup:
  cgrp_trick_bpf__destroy(skel);
  return 0;
}
