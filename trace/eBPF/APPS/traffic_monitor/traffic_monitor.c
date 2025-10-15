#include "traffic_monitor.skel.h"
#include "traffic_monitor.h"
#include <linux/bpf.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <bpf/libbpf.h>

bool outFlag = true;
int minRate = 1000;		/* cgroup rate limit in Mbps */
int rate = 1;		/* can grow if rate conserving is enabled */
int dur = 1;
bool stats_flag = true;
bool loopback_flag;
bool debugFlag;
bool work_conserving_flag;
bool no_cn_flag;
bool edt_flag;

#define DEBUGFS "/sys/kernel/debug/tracing/"

static void read_trace_pipe2(void)
{
	int trace_fd;
	FILE *outf;
	char *outFname = "hbm_out.log";
	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0) {
		printf("Error opening trace_pipe\n");
		return;
	}
//	Future support of ingress
//	if (!outFlag)
//		outFname = "hbm_in.log";
	outf = fopen(outFname, "w");
	if (outf == NULL)
		printf("Error creating %s\n", outFname);
	while (1) {
		static char buf[4097];
		ssize_t sz;
		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
			if (outf != NULL) {
				fprintf(outf, "%s\n", buf);
				fflush(outf);
			}
		}
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig){
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


int main()
{
    struct traffic_monitor_bpf *skel;


    int cgroup_fd;
    const char *cgroup_path = "/sys/fs/cgroup/system.slice/docker-427dde639874fe12d1a723e5097d74db3ba80b2761e68939ad945b9c07cfa395.scope";
    libbpf_set_print(libbpf_print_fn);
    skel = traffic_monitor_bpf__open_and_load();

    if (!skel){
        fprintf(stderr, "failed to open/load skeleton\n");
        return 1;
    }

    cgroup_fd = open(cgroup_path, O_RDONLY);
    if(cgroup_fd < 0){
        fprintf(stderr, "Falied to open cgroup path %s: %s\n", cgroup_path, strerror(errno));
        goto cleanup;
    }

    int map_fd = bpf_map__fd(skel->maps.queue_stats);
    if (map_fd == -1) {
        goto cleanup;
    }
    int queue_index = 0;
    struct traffic_queue_stats tqs = {0};
    tqs.rate = rate;
    tqs.stats = stats_flag ? 1: 0;
    tqs.loopback = loopback_flag ? 1: 0;
    tqs.no_cn = no_cn_flag ? 1:0;

    // 更新数据
    if(bpf_map_update_elem(map_fd, &queue_index, &tqs, BPF_ANY)){
        printf("ERROR: Could not update map element\n");
        goto cleanup;
    }

    struct bpf_link *link_egress = NULL;
    link_egress = bpf_program__attach_cgroup(skel->progs.traffic_monitor_handler, cgroup_fd);
    if(!link_egress){
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }


    printf("Successfully attached BPF program to cgroup %s\n", cgroup_path);
    printf("Press Ctrl+C to stop.\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);


    while(!exiting){
        /* bpf_map__lookup_elem(skel->maps.queue_stats, &queue_index, sizeof(int),&tqs, sizeof(tqs), 0); */
        bpf_map_lookup_elem(map_fd, &queue_index, &tqs);
        /* tqs.rate++; */
        /* if(bpf_map_update_elem(map_fd, &queue_index, &tqs, BPF_ANY)){ */
        /*     printf("ERROR: Could not update map element\n"); */
        /*     goto cleanup; */
        /* } */
        printf("firstPacketTime: %lld, lastPacketTime: %lld\n", tqs.firstPacketTime, tqs.lastPacketTime);
        sleep(5);
    }
    printf("exiting...\n");

cleanup:
    if (link_egress)
        bpf_link__destroy(link_egress);
    if (cgroup_fd >= 0){
        close(cgroup_fd);
    }
    traffic_monitor_bpf__destroy(skel);


    return 0;
}

