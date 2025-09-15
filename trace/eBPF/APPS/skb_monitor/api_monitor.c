#include <stdio.h>
#include "api_monitor.skel.h" 
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>

#define TASK_COMM_LEN 16
struct net_event {
    bool is_ingress;
    __u32 pid;
    __u64 len;
    char comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};



static volatile bool exiting = false;

static void sig_handler(int sig){
    exiting = true;
}

static int handle_net_event(void *ctx, void *data, size_t data_sz) {
    const struct net_event *e = data;
    if (data_sz < sizeof(struct net_event)) {
        fprintf(stderr, "Invalid event size: %zu\n", data_sz);
        return 0;
    }
    char saddr_str[INET_ADDRSTRLEN], daddr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->saddr, saddr_str, sizeof(saddr_str));
    inet_ntop(AF_INET, &e->daddr, daddr_str, sizeof(daddr_str));
    printf("Event: ingress=%d, pid=%u, comm=%s, saddr=%s, daddr=%s, sport=%u, dport=%u, len=%llu\n",
           e->is_ingress, e->pid, e->comm, saddr_str, daddr_str, e->sport, e->dport, e->len);
    return 0;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


int main()
{

    struct bpf_link *link_egress = NULL;
    struct bpf_link *link_ingress = NULL;
    struct ring_buffer *rb = NULL;

    int cgroup_fd;
    const char *cgroup_path = "/sys/fs/cgroup/system.slice/docker-427dde639874fe12d1a723e5097d74db3ba80b2761e68939ad945b9c07cfa395.scope";
    libbpf_set_print(libbpf_print_fn);
    struct api_monitor_bpf *skel;
    int err,interval = 5;
    skel = api_monitor_bpf__open_and_load();
    if(!skel){
        fprintf(stderr, "failed to open/load skeleton\n");
        return 1;
    }

    cgroup_fd = open(cgroup_path, O_RDONLY);
    if(cgroup_fd < 0){
        fprintf(stderr, "Falied to open cgroup path %s: %s\n", cgroup_path, strerror(errno));
        goto cleanup;
    }

    link_egress = bpf_program__attach_cgroup(skel->progs.apiserver_monitor, cgroup_fd);
    if(!link_egress){
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    /* link_ingress = bpf_program__attach_cgroup(skel->progs._hbm_in_cg, cgroup_fd); */
    /* if(!link_ingress){ */
    /*     fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno)); */
    /*     goto cleanup; */
    /* } */


    /* err = api_monitor_bpf__attach(skel); */
    /* if(err) { */
    /*     fprintf(stderr, "failed to attach\n"); */
    /*     goto cleanup; */
    /* } */

    printf("Successfully attached BPF program to cgroup %s\n", cgroup_path);
    printf("Press Ctrl+C to stop.\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);


    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_net_event, NULL, NULL);
    if(!rb){
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }


    while(!exiting){
        err = ring_buffer__poll(rb, 100);
        if(err == -EINTR){
            err = 0;
            break;
        }
        if (err < 0){
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        /* sleep(interval); */
    }

cleanup:
    if(rb) {
        ring_buffer__free(rb);
    }
    if (link_egress)
        bpf_link__destroy(link_egress);
    /* if (link_ingress) */
    /*     bpf_link__destroy(link_ingress); */
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    api_monitor_bpf__destroy(skel);
    return 0;
}

