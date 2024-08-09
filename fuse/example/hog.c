#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
int file_size;
static int hog_read(){}
static int hog_open(){}
static int hog_readdir(){}
static int hog_getattr(){}


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
