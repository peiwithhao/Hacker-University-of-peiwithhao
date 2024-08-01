#include <cstdio>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>


#define QUEUE_DEPTH 1
/* 

 //Passed in for io_uring_setup(2). Copied back with updated info on success
struct io_uring_params {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u32 sq_thread_cpu;
	__u32 sq_thread_idle;
	__u32 features;
	__u32 wq_fd;
	__u32 resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

*/


int io_uring_setup(__int32_t entries, struct io_uring_params *params){
    return (int)syscall(__NR_io_uring_setup, entries, params);
}

int io_uring_enter(unsigned int fd, unsigned int to_submit,
                   unsigned int min_complete, unsigned int flags,
                   void *argp, size_t argsz){
    return (int)syscall(__NR_io_uring_enter, fd, to_submit,
                        min_complete, flags, 
                        argp, argsz);
}

/* 
 * Description: use sys_io_uring_setup, 
 * learning and getting strange geeky peace
 * 
 * 
 */


int hogo_setup_io_uring(){
    int io_uring_fd;
    int sring_sz, cring_sz; 
    struct io_uring_params iup;
    io_uring_fd = io_uring_setup(QUEUE_DEPTH, &iup);
    if(io_uring_fd < 0){
        perror("io_uring_setup");
        return 1;
    }
    /* seems to pass the io_uring_registers */
        
}





int main(int argc, char **argv){
    /* 构造io_uring_params */
    hogo_setup_io_uring(); 
}
