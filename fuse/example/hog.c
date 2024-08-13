#define FUSE_USE_VERSION 26
#include <string.h>
#include <unistd.h>
#include <fuse.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int file_size;
static const char* task_path = "/task";
static const char* seqop_path = "/seqop";
static const char* iobuf_path = "/iobuf";
static const char* bpfprog_path = "/bpfprog";

static int hog_read(const char *path, char *buf, size_t size, off_t off,
		     struct fuse_file_info *file_info){
    if(strcmp(path, bpfprog_path) == 0){
        while(1){
            sleep(100);
        }
    }

    for(int i = 0; i < 3; i++){
        sleep(1);
    }
    return size;
}

static int hog_open(const char *path, struct fuse_file_info * file_info){
    return 0;
}

static int hog_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off,
			struct fuse_file_info *file_info){
    /* 返回当前目录和上级目录信息 */
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    return 0;
}
static int hog_getattr(const char *path, struct stat *stbuf){
    
    int result = 0;
    memset(stbuf, 0, sizeof(struct stat));
    if(strcmp(path, "/") == 0){
        stbuf->st_mode = S_IFDIR | 0755;    //设置文件类型和权限
        stbuf->st_nlink = 2;    //硬连接的数量,一般目录都会有两个,一个是他自己,一个是他父目录的连接
    }else if(strcmp(path, task_path) == 0){
        stbuf->st_mode = S_IFREG | 0666;    //regular file
        stbuf->st_nlink = 1;
        stbuf->st_size = file_size;
        stbuf->st_blocks = 0;   //表示文件磁盘上没有实际分配的存储块
    }else if(strcmp(path, seqop_path)){
        stbuf->st_mode = S_IFREG | 0666;    //regular file
        stbuf->st_nlink = 1;
        stbuf->st_size = file_size;
        stbuf->st_blocks = 0;   //表示文件磁盘上没有实际分配的存储块
    }else if(strcmp(path, iobuf_path)){
        stbuf->st_mode = S_IFREG | 0666;    //regular file
        stbuf->st_nlink = 1;
        stbuf->st_size = file_size;
        stbuf->st_blocks = 0;   //表示文件磁盘上没有实际分配的存储块
    }else if(strcmp(path, bpfprog_path)){
        stbuf->st_mode = S_IFREG | 0666;    //regular file
        stbuf->st_nlink = 1;
        stbuf->st_size = file_size;
        stbuf->st_blocks = 0;   //表示文件磁盘上没有实际分配的存储块
    }else
        result = -ENOENT;
    return result;
}


static struct fuse_operations fops = {
    .read  = hog_read,
    .open  = hog_open,
    .getattr = hog_getattr,
    .readdir = hog_readdir
};

int main(int argc, char **argv){
    file_size = 0x1000;
    return fuse_main(argc, argv, &fops, NULL);

}
