#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/syscall.h>
#include "fault_injector.skel.h"


static volatile int exiting = 0;
void sig_handler(int signo) { exiting = 1; }

int main(int argc, char **argv)
{
    struct fault_injector_bpf *skel;
    int err, filter_pid = atoi(argv[1]);
    skel = fault_injector_bpf__open_and_load();
    if(!skel){
        fprintf(stderr, "failed to open/load skeleton\n");
        return 1;
    }
    bpf_map_update_elem(bpf_map__fd(skel->maps.filter), &(uint32_t){0}, &filter_pid, BPF_ANY);


    err = fault_injector_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach\n");
        goto cleanup;
    }

    getchar();

cleanup:
    fault_injector_bpf__destroy(skel);
    return 0;
}

