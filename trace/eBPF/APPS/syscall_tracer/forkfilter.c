// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "forkfilter.h"
#include "forkfilter.skel.h"
#include <pthread.h>

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF forkfilter demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./forkfilter [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

/* head list for ns_famiy */
static struct ns_family *ns_head;
static int ns_nr = 0; 
static pthread_mutex_t ns_head_lock;


static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static struct ns_family *create_new_ns_family(unsigned int new_inum){
    struct ns_family * new = (struct ns_family *)malloc(sizeof(struct ns_family));
    memset(new, 0, sizeof(struct ns_family));
    if(!new){
        perror("malloc");
        exit(1);
    }
    new->process_nr = 0;
    new->ns_inum = new_inum;
    pthread_mutex_lock(&ns_head_lock);
    if(!ns_nr){
        new->ns = 0;
    }else{
        new->ns = ns_head;
    }
    ns_nr++;
    ns_head = new;
    pthread_mutex_unlock(&ns_head_lock);
    return new;
}

static int unlink_ns_family(struct ns_family *uns){
    if (uns == NULL || ns_head == NULL) {
        return -1;  // 如果输入节点为空或链表为空，返回错误
    }
    // 特殊处理头节点的情况
    if (ns_head == uns) {
        ns_head = uns->ns;  // 更新头节点指针
        return 0;           // 成功删除
    }
    struct ns_family *ns_tmp = ns_head;

    // 遍历链表，查找要删除的节点
    while (ns_tmp->ns != NULL) {
        // 找到要删除的节点
        if (ns_tmp->ns == uns) {
            ns_tmp->ns = uns->ns;  // 将当前节点的指针指向要删除节点的下一个节点
            return 0;               // 成功删除
        }
        ns_tmp = ns_tmp->ns;  // 继续遍历
    }
    return -1;
}


static int add_process(struct ns_family *ns, int pid){
    int newpid = -1;
    struct ns_family * ns_current = ns;
    for(int i = 0; i < ns_current->pid_sz; i++){
        if(ns_current->pid[i] == pid){
            newpid = 0;
            break;
        }
    }
    /* already have this pid */
    if(!newpid){
        return 0;
    }
    pthread_mutex_lock(&ns_head_lock);
    unlink_ns_family(ns_current);
    ns_current = (struct ns_family *)realloc(ns_current, sizeof(struct ns_family) + (++ns_current->process_nr)*sizeof(long));
    /* clean extended space*/
    if(ns_current->process_nr > ns_current->pid_sz){
        memset(ns_current->pid + ns_current->pid_sz, 0, (ns_current->process_nr - ns_current->pid_sz)*sizeof(int));
    }
    if(!ns_current){
        perror("realloc");   
        exit(1);
    }
    /* reset the pid array size */
    if(ns_current->process_nr > ns_current->pid_sz){
        ns_current->pid_sz = ns_current->process_nr;
    }
    ns_current->ns = ns_head;
    ns_head = ns_current;
    pthread_mutex_unlock(&ns_head_lock);

    /* find free location */
    for(int i = 0; i < ns_current->pid_sz; i++){
        if(ns_current->pid[i] == 0){
            ns_current->pid[i] = pid;
            break;
        }
    }
    return 1;
}

static void del_process(struct ns_family *ns, int pid){
    int delflag = -1;
    for(int i = 0; i < ns->pid_sz; i++){
        if(ns->pid[i] == pid){
            ns->pid[i] = 0;
            delflag = 0;
            break;
        }
    }
    if(!delflag){
        ns->process_nr--;
    }
}


static volatile bool exiting = false;

static void sig_handler(int sig)
{
    struct ns_family *ns_tmp;
    printf("\n\033[32m[!]Totally:\033[0m\n");
    pthread_mutex_lock(&ns_head_lock);
    ns_tmp = ns_head;
    while(ns_tmp){
        printf("[+]NAMESPACE ID: %-7u PROCESS_NR: %d PID_ARRAY_SZ: %d\n", ns_tmp->ns_inum, ns_tmp->process_nr, ns_tmp->pid_sz);
        for(int i = 0; i < ns_tmp->pid_sz; i++){
            if(ns_tmp->pid[i] <= 0) continue;
            printf("[+]Host PID: %d\n", ns_tmp->pid[i]);
        }
        ns_tmp = ns_tmp->ns;
    }
    pthread_mutex_unlock(&ns_head_lock);
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
    struct ns_family *ns_tmp;
	char ts[32];
	time_t t;
    int newns_flag = -1;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->mode == EXIT_EVENT) {
		printf("%-8s %-5s %-16s %-7d %-7d %-11u [%u]", ts, "EXIT", e->comm, e->pid, e->ppid, e->ns_inum,
		       e->exit_code);
		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else if (e->mode == EXEC_EVENT){
		printf("%-8s %-5s %-16s %-7d %-7d %-11u %s\n", ts, "EXEC", e->comm, e->pid, e->ppid, e->ns_inum,
		       e->filename);
	}
    //Get the map
    pthread_mutex_lock(&ns_head_lock);
    ns_tmp = ns_head;
    while(ns_tmp){
        /* found the exsit ns family */
        if(ns_tmp->ns_inum == e->ns_inum){
            newns_flag = 0;
            break;
        }
        ns_tmp = ns_tmp->ns;
    }
    pthread_mutex_unlock(&ns_head_lock);
    
    /* new */
    if(newns_flag){
        ns_tmp = create_new_ns_family(e->ns_inum);
    }

    switch(e->mode){
        case EXEC_EVENT:
            add_process(ns_tmp, e->pid);
            break;
        case EXIT_EVENT:
            del_process(ns_tmp, e->pid);
            break;
        default:
            break;
    }

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct forkfilter_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    /* Initialize the ns_head lock */
    pthread_mutex_init(&ns_head_lock, NULL);

	/* Load and verify BPF application */
	skel = forkfilter_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = forkfilter_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = forkfilter_bpf__attach(skel);
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

	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %-11s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID", "PIDNSINUM",
	       "FILENAME/EXIT CODE");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	forkfilter_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
