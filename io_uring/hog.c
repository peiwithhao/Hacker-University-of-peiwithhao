#include <linux/fs.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>

#define QUEUE_DEPTH 1
#define BLOCK_SZ 0x400

/* This is x86 specific */
#define read_barrier()  __asm__ __volatile__("":::"memory")
#define write_barrier() __asm__ __volatile__("":::"memory")

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

struct file_info {
    off_t file_sz;
    struct iovec iovecs[]; 
};

void output_to_console(char *buf, int len){
    while(len--){
        fputc(*buf++, stdout);
    }
}

off_t get_file_sz(int file_fd){
    struct stat stat_buffers;
    if(fstat(file_fd, &stat_buffers)<0){
        perror("fstat");
        return -1;
    }
    if(S_ISBLK(stat_buffers.st_mode)) {
        unsigned long long bytes;
        if(ioctl(file_fd, BLKGETSIZE64, &bytes) != 0){
            perror("ioctl");
            return -1;
        }
    }else if(S_ISREG(stat_buffers.st_mode))
        return stat_buffers.st_size;
    return -1;
}

int io_uring_setup(__int32_t entries, struct io_uring_params *params){
    return (int)syscall(__NR_io_uring_setup, entries, params);
}

int io_uring_enter(unsigned int fd, unsigned int to_submit,
                   unsigned int min_complete, unsigned int flags){
    return (int)syscall(__NR_io_uring_enter, fd, to_submit,
                        min_complete, flags, 
                        NULL, 0);
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
    
    memset(&iup, 0 ,sizeof(iup));
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
    if (s->sqes == ((void *)-1)) {
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
size_t write_to_sq(char *file_path, struct submittors *s){
    struct file_info *fi;
    int file_fd = open(file_path, O_RDONLY);
    unsigned int current_block = 0, index = 0, tail = 0, next_tail = 0;
    if(file_fd < 0){
        perror("open");
        return 1;
    }
    struct hog_io_sq_ring *sring = &s->sq_ring;
    /* Calculate the blocks num of file */
    off_t file_sz = get_file_sz(file_fd); 
    off_t bytes_remain = file_sz;
    int blocks = (int)file_sz/BLOCK_SZ;
    if(file_sz % BLOCK_SZ){
        blocks++;
    }

    fi = malloc(sizeof(*fi) + sizeof(struct iovec) * blocks);
    if(!fi){
        fprintf(stderr, "Unable to allocate memory\n");
        return 1;
    }
    fi->file_sz = file_sz;
    while(bytes_remain){
        off_t bytes_to_read = bytes_remain;
        if(bytes_to_read > BLOCK_SZ){
            bytes_to_read = BLOCK_SZ;
        }
        fi->iovecs[current_block].iov_len = bytes_to_read;
        void *buf;
        if(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ)){
            perror("posix_memalign");
            return 1;
        }
        fi->iovecs[current_block].iov_base = buf;
        current_block++;
        bytes_remain -= bytes_to_read;
    }
    /* Add our submission queue entry */ 
    next_tail = tail = *sring->tail;
    next_tail++;
    read_barrier();
    index = tail & *s->sq_ring.ring_mask;
    struct io_uring_sqe *sqe = &s->sqes[index];
    sqe->fd = file_fd;
    sqe->flags = 0;
    sqe->opcode = IORING_OP_READV;
    sqe->addr = (unsigned long)fi->iovecs;
    sqe->len = blocks;
    sqe->off = 0;
    sqe->user_data = (unsigned long long)fi;
    sring->array[index] = index;
    tail = next_tail;

    if(*sring->tail != tail){
        *sring->tail = tail;
        write_barrier();
    }

    int ret = io_uring_enter(s->ring_fd, 1, 1, IORING_ENTER_GETEVENTS);
    if(ret < 0){
        perror("io_uring_enter");
        return 1;
    }
    return 0; 
}

/* read from cqring */
size_t read_from_cq(struct submittors *s){
    struct file_info *fi;
    struct hog_io_cq_ring *cring = &s->cq_ring;
    struct io_uring_cqe *cqe;
    unsigned head, repeat = 0;
    head = *cring->head;
    
    do{
        read_barrier();
        if(head == *cring->tail){
            break;
        }
        cqe = &cring->cqes[head & *s->cq_ring.ring_mask];
        fi = (struct file_info*)cqe->user_data;
        if(cqe->res < 0){
            fprintf(stderr, "Error: %s\n", strerror(abs(cqe->res)));
        }
        int blocks = (int)fi->file_sz/BLOCK_SZ;
        if(fi->file_sz % BLOCK_SZ){
            blocks++;
        }
        for(int i = 0; i < blocks; i++)
            output_to_console(fi->iovecs[i].iov_base, fi->iovecs[i].iov_len);
        head++;
    }while(1);
    
    *cring->head = head;
    write_barrier();
    return 0;
}




int main(int argc, char **argv){
    /* Construct the submittors which include the sq_ring and cq_ring */
    struct submittors s;

    /* 构造io_uring_params */
    if(hog_setup_io_uring(&s)){
        fprintf(stderr, "unable to setup uring!\n");
    }

    for(int i = 1; i < argc; i++){
        if(write_to_sq(argv[i], &s)){
            fprintf(stderr, "Error reading file");
            return 1;
        }
        read_from_cq(&s);
    }
    return 0;
}
