#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/syscall.h>
#include "syscall_monitor.skel.h"
#include "syscall_monitor.h"
#include "include/uthash.h"

#define ERRNO_NR 256 //errno --list | wc -l  >> 134
static volatile int exiting = 0;
void sig_handler(int signo) { exiting = 1; }

struct sys_count_ts {
    uint64_t count;
    uint64_t timestamp;
};

struct syscall_statistics {
    int syscall_id;     /* key */
    struct sys_count_ts syscall_nr[ERRNO_NR]; /* [errno][count] */
    uint64_t total_count;
    UT_hash_handle hh; /* make this structure hashable */
};

struct syscall_statistics *global_sys_stat = NULL;

void update_sysHashtable(struct syscall_key *key, struct syscall_val *val){
    struct syscall_statistics *ss;
    HASH_FIND_INT(global_sys_stat, &(key->id), ss);
    /* first count */
    if (ss != NULL){
        /* judge the error code */
        if (-key->err > (ERRNO_NR-1)){
            return;
        }else {
            int errno_id;
            errno_id = key->err > 0 ? 0: -key->err;
            ss->syscall_nr[errno_id].count += val->count;
            ss->syscall_nr[errno_id].timestamp += val->total_ns;
        }
        ss->total_count += val->count;
    }else{
        ss = (struct syscall_statistics *)calloc(1, sizeof(struct syscall_statistics));
        ss->syscall_id = key->id;
        if (-key->err > (ERRNO_NR-1)){
            return;
        }else {
            int errno_id;
            errno_id = key->err > 0 ? 0: -key->err;
            ss->syscall_nr[errno_id].count += val->count;
            ss->syscall_nr[errno_id].timestamp += val->total_ns;
        }
        ss->total_count = val->count;
        HASH_ADD_INT(global_sys_stat, syscall_id, ss);
    }
}

void print_sysHashtable(void){
    struct syscall_statistics *current;
    struct syscall_statistics *tmp;
    HASH_ITER(hh, global_sys_stat, current, tmp) {
        printf("syscall_id: %d\n", current->syscall_id);
        printf("%-10s %-10s %-10s %-15s\n", "ERRNO", "COUNT", "RATIO", "AVG_LATENCY(us)");
        for (int i = 0; i < ERRNO_NR; i++){
            if (current->syscall_nr[i].count == 0){
                continue;
            }else {
                long count = current->syscall_nr[i].count;
                long total_ns = current->syscall_nr[i].timestamp;
                long total_count = current->total_count;
                float ratio = count ? (float)count/(float)total_count : 0;
                float avg_us = count ? (float)total_ns / (float)count/ 1000:0;
                printf("%-10d %-10ld %-10lf %-15lf\n", i, count, ratio, avg_us);
            }
        }
    }
}

void free_sysHashtable(void){
    struct syscall_statistics *current;
    struct syscall_statistics *tmp;
    HASH_ITER(hh, global_sys_stat, current, tmp){
        HASH_DEL(global_sys_stat, current);
        free(current);
    } 
}

int main(int argc, char **argv)
{
    struct syscall_monitor_bpf *skel;
    int err, interval = 5, filter_pid = atoi(argv[1]);
    // 解析参数省略，可以加 getopt_long 支持

    skel = syscall_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load skeleton\n");
        return 1;
    }

    // 设置过滤
    bpf_map_update_elem(bpf_map__fd(skel->maps.filter), &(uint32_t){0}, &filter_pid, BPF_ANY);

    err = syscall_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach\n");
        goto cleanup;
    }

    printf("Tracing syscalls... Press Ctrl+C to exit.\n");
    signal(SIGINT, sig_handler);

    int loop = 0;
    while (!exiting) {
        sleep(interval);
        /* char filename[0x100]; */
        /* snprintf(filename, sizeof(filename), "results/syscall_stats_%d.txt", loop); */
        /* loop++; */
        /* FILE *fp = fopen(filename, "w"); */
        /* if(!fp){ */
        /*     perror("fopen"); */
        /*     break; */
        /* } */

        // 遍历 syscalls map
        struct syscall_key key = {}, next_key = {};
        struct syscall_val val = {};
        int map_fd = bpf_map__fd(skel->maps.syscalls);

        /* fprintf(fp, "%-20s %-10s %-10s %-10s\n", "SYSCALL", "ERRNO", "COUNT", "AVG_LATENCY(us)"); */
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            bpf_map_lookup_elem(map_fd, &next_key, &val);
            /* fprintf(fp, "%-20u %-10d %-10lu %-10lu\n", */
            /*     next_key.id, next_key.err, val.count, */
            /*     val.count ? val.total_ns / val.count / 1000 : 0); */

            update_sysHashtable(&next_key, &val);


            bpf_map_delete_elem(map_fd, &next_key);
            key = next_key;
        }  
        print_sysHashtable();
        free_sysHashtable();
        printf("[+]Loop %d Done\n", loop);
        /* fclose(fp); */
    }

cleanup:
    syscall_monitor_bpf__destroy(skel);
    return 0;
}
