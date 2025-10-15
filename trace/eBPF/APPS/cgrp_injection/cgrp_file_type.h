#ifndef CGRP_FILE_TYPE_H
#define CGRP_FILE_TYPE_H

// this file created for define the file type

#define TYPE_MEMORY_CURRENT      1
#define TYPE_MEMORY_MAX          2
#define TYPE_MEMORY_SWAP_CURRENT 3
#define TYPE_MEMORY_SWAP_MAX     4
#define TYPE_CPU_WEIGHT          5
#define TYPE_CPU_MAX             6
#define TYPE_RDMA_MAX            7
#define TYPE_RDMA_CURRENT        8
#define TYPE_MISC_CURRENT        9
#define TYPE_PIDS_MAX            10
#define TYPE_PIDS_CURRENT        11


#define FILE_NAME_MAX_NR 32
#define CGROUP_V2_MAGIC 1667723888


#define MEMORY_CURRENT          "memory.current"
#define MEMORY_MAX              "memory.max"
#define MEMORY_SWAP_CURRENT     "memory.swap.current"
#define MEMORY_SWAP_MAX         "memory.swap.max"
#define CPU_WEIGHT              "cpu.weight"
#define CPU_MAX                 "cpu.max"
#define RDMA_MAX                "rdma.max"
#define RDMA_CURRENT            "rdma.current"
#define MISC_CURRENT            "misc.current"
#define PIDS_MAX                "pids.max"
#define PIDS_CURRENT            "pids.current"


#endif

