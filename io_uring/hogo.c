#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>


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




int main(int argc, char **argv){
        
}
