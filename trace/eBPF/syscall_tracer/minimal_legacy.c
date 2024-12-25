/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include "minimal_legacy.skel.h"
#include "minimal_legacy.h"
#include "syscalls_table.h"

static FILE *of = NULL;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct syscall_event *event = data;
    fprintf(of, "%-20s\t[",syscalls[event->syscall_id].name);
    for(int i = 0; i < syscalls[event->syscall_id].num_args; i++){
      if (i < syscalls[event->syscall_id].num_args - 1) {
            fprintf(of, "%-20.20lu, ", event->args[i]);
        } else {
            fprintf(of, "%-20.20lu", event->args[i]);
        }
    }
    fprintf(of, "]\n");
    return 0;
}



static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct minimal_legacy_bpf *skel;
	struct ring_buffer *rb = NULL;
	int opt;
	int err;
	pid_t pid;
	unsigned index = 0;
	int pid_set = -1;

	// 解析命令行选项
    	while ((opt = getopt(argc, argv, "p:o:")) != -1) {
		switch (opt) {
	    		case 'p':
			// 将传递的参数转换为整数
				pid = (pid_t)atoi(optarg);
				pid_set = 0;
				break;
			case 'o':
				of = fopen(optarg, "w");
				break;
			default:
				fprintf(stderr, "Usage: %s -p <number>\n", argv[0]);
				return EXIT_FAILURE;
		}
	} 
	if (pid_set == -1) {
		fprintf(stderr, "Error: -p option is required with a number.\n");
		return EXIT_FAILURE;
	}
	if(!of){
		of = stdout;
	}
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = minimal_legacy_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
// pid = getpid();

	err = bpf_map__update_elem(skel->maps.my_pid_map, &index, sizeof(index), &pid,
				   sizeof(pid_t), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Error updating map with pid: %s\n", strerror(err));
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = minimal_legacy_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Listening for syscalls...\n");

	// 主循环：等待事件并处理
    	printf("系统调用:\t[参数1, \t 参数2, \t 参数3, \t 参数4, \t 参数5, \t 参数6\n");
	while (1) {
	    int err = ring_buffer__poll(rb, 100 /* ms */);
	    if (err < 0) {
		fprintf(stderr, "Error polling perf buffer: %d\\n", err);
		break;
	    }
	}



//	for (;;) {
//		fprintf(stderr, ".");
//		sleep(1);
//	}

cleanup:
	if(of){
		fclose(of);
	}
	ring_buffer__free(rb);
	minimal_legacy_bpf__destroy(skel);
	return -err;
}
