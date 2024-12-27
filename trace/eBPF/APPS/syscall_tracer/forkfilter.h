/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __FORKFILTER_H
#define __FORKFILTER_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127
#define event_mode int

#define FORK_EVENT 1
#define EXEC_EVENT 2
#define EXIT_EVENT 3		

struct event {
	int pid;
	int ppid;
	unsigned int ns_inum;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	event_mode mode;
};

struct ns_family{
    struct ns_family* ns; 
    unsigned ns_inum;
    int process_nr;
    int pid_sz;
    int pid[];
};

#endif /* __FORKFILTER_H */
