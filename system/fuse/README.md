# FUSE 框架介绍
FUSE全名(Filesystem in Userspace)用户下的文件系统,
我们知道的文件系统有很多,比如ext,ext2, fat32等等,这些实际存在的文件系统都被linux中实现的VFS所统一化,用户只需要与VFS所进行交互,其中具体文件系统的函数实现只需要遵守VFS向下提供的接口即可

而fuse则提供了一个用户自建文件系统的功能,当然其也是需要使用VFS来进行交互,下面给出fuse在实现之后用户调用的过程:
1. 用户态调用glibc open()函数接口,触发内核sys_open;
2. sys_open调用fuse inode节点定义的open函数
3. inode中的open生成request消息,通过/dev/fuse发送rquest消息到用户态libfuse
4. libfuse调用fuse_application用户自定义的open函数据,并将返回值通过/dev/fuse通知给内核;
5. 内核受到request消息的处理完成的唤醒,将结果返回VFS,然后再返回给用户

# 使用技巧
首先就是如何使用他,我们可以看他的github仓库[libfuse/libfuse](https://github.com/libfuse/libfuse?tab=readme-ov-file)
这里我们所需要的就是类似于写`file_operations`一样,补充下面的结构体`static struct fuse_operations fops`
这个数据结构在`fuse/fuse.h`文件中包含

当填充完上述结构体并且相继实现了各自函数之后,我们可以在main函数中调用`fuse_main()`
下面是官方给出的解释:
```c
 * This is for the lazy.  This is all that has to be called from the
 * main() function.
 *
 * This function does the following:
 *   - parses command line options (-d -s and -h)
 *   - passes relevant mount options to the fuse_mount()
 *   - installs signal handlers for INT, HUP, TERM and PIPE
 *   - registers an exit handler to unmount the filesystem on program exit
 *   - creates a fuse handle
 *   - registers the operations
 *   - calls either the single-threaded or the multi-threaded event loop
```
可以看到他做了很多事情

所以这里我们需要做的第一步就是编写他的fops以及实现函数:
```c
static struct fuse_operations fops = {
    .read  = hog_read,
    .open  = hog_open,
    .getattr = hog_getattr,
    .readdir = hog_readdir
};
```
这个结构体我们需要在宏定义添加下面版本的宏,我们需要大于等于26才能使用较为现代化的版本
```c
#if FUSE_USE_VERSION < 26
#  include "fuse_compat.h"
#  undef fuse_main
#  if FUSE_USE_VERSION == 25
```

然后我们只需要在main函数进行注册即可
```c
int main(int argc, char **argv){
    file_size = 0x1000;
    return fuse_main(argc, argv, &fops, NULL);

}
```
要想使用这个我们的用户文件系统,还需要手动执行命令例如
```sh
 mkdir -p /tmp/fuse_mount && ./hog_fs /tmp/fuse_mount
```
这个操作代表我们将该fuse文件系统挂载到`/tmp/fuse_mount`目录下,然后我们正常使用其中的接口即可

至于编译阶段我们可以直接将`libfuse/libfuse`项目编译为一个静态库然后链接到程序即可
这里的编译选项我们可以直接照抄`libfuse/libfuse`程序库的example代码里面的编译选项
```sh
gcc -no-pie -static `pkg-config fuse3 --cflags --libs` hog_fs.c -o fs_extract/hog_fs -L./ -lfuse3 
```




# 参考
[fuse框架分析与实战](https://cloud.tencent.com/developer/article/1006138)
[Linux Kernel pwn](https://blog.wohin.me/posts/pawnyable-0304/)
