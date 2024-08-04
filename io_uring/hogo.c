#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
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

struct hog_io_sq_ring{
    unsigned int * head;
    unsigned int * tail;
    unsigned int * ring_mask;
    unsigned int * ring_entries;
    unsigned int * flags;
    unsigned int * array;
};

struct hog_io_cq_ring{
    unsigned int * head;
    unsigned int * tail;
    unsigned int * ring_mask;
    unsigned int * ring_entries;
    struct io_uring_cqe *cqes;
};

struct submittors{
    int ring_fd;
    struct hog_io_sq_ring sq_ring;
    struct io_uring_sqe *sqes;
    struct hog_io_cq_ring cq_ring;
};



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
int hog_setup_io_uring(struct submittors * s){
    int sring_sz, cring_sz; 
    void *sq_ptr, *cq_ptr;
    struct io_uring_params iup;
    struct hog_io_sq_ring *sring = &s->sq_ring;
    struct hog_io_cq_ring *cring = &s->cq_ring;

    s->ring_fd = io_uring_setup(QUEUE_DEPTH, &iup);
    if(s->ring_fd < 0){
        perror("io_uring_setup");
        return 1;
    }
    /* seems to pass the io_uring_registers */
    sring_sz = iup.sq_off.array + iup.sq_entries * sizeof(unsigned);
    cring_sz = iup.cq_off.cqes + iup.cq_entries * sizeof(struct io_uring_cqe);

    /* if IORING_FEAT_SINGLE_MMAP is set, we can do away with the second mmap()
     * ONE MMAP FOR TWO RINGS!
     * */
    if(iup.features & IORING_FEAT_SINGLE_MMAP){
        if(cring_sz > sring_sz){
            sring_sz = cring_sz;
        }
        cring_sz = sring_sz;
    }

    /* Map in the submission and completion queue ring buffers */
    sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, 
                  MAP_SHARED | MAP_POPULATE, 
                  s->ring_fd, IORING_OFF_SQ_RING);
    if(sq_ptr == MAP_FAILED){
        perror("mmap");
        return 1;
    }
    if(iup.features & IORING_FEAT_SINGLE_MMAP){
        cq_ptr = sq_ptr;
    }else{
        /* Map in the completion queue ring buffers for elden kernel version*/
        cq_ptr = mmap(0, cring_sz, PROT_READ | PROT_WRITE, 
                      MAP_SHARED | MAP_POPULATE, 
                      s->ring_fd, IORING_OFF_CQ_RING);
        if(cq_ptr == MAP_FAILED){
            perror("mmap");
            return 1;
        }
    }
    /* Save Useful fields to the submittors' sq_ring */
    sring->head = sq_ptr + iup.sq_off.head;
    sring->tail = sq_ptr + iup.sq_off.tail;
    sring->flags = sq_ptr + iup.sq_off.flags;
    sring->array = sq_ptr + iup.sq_off.array;
    sring->ring_entries = sq_ptr + iup.sq_off.ring_entries;
    sring->ring_mask = sq_ptr + iup.sq_off.ring_mask;

    /* Map in the submission queue entries array */
    s->sqes = mmap(0, iup.sq_entries * sizeof(struct io_uring_sqe),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, 
                   s->ring_fd, IORING_OFF_SQES);
    if(s->sqes == MAP_FAILED){
        perror("mmap");
        return 1;
    }
    /* Save Userful fields to the submittors' cq_ring */
    cring->head = cq_ptr + iup.cq_off.head;
    cring->tail = cq_ptr + iup.cq_off.tail;
    cring->ring_mask = cq_ptr + iup.cq_off.ring_mask;
    cring->ring_entries = cq_ptr + iup.cq_off.ring_entries;
    cring->cqes = cq_ptr + iup.cq_off.cqes;
    return 0;
}


/* Write to the sqring */
size_t write_to_sq();

/* read from cqring */
size_t read_from_cq();




int main(int argc, char **argv){
    /* Construct the submittors which include the sq_ring and cq_ring */
    struct submittors s;

    /* 构造io_uring_params */
    hog_setup_io_uring(&s); 
}
