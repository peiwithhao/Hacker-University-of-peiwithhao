#ifndef SYSCALL_MONITOR_H
#define SYSCALL_MONITOR_H

struct syscall_key {
    uint32_t id;
    int32_t err;
};

struct syscall_val {
    uint64_t count;
    uint64_t total_ns;
};

#endif


