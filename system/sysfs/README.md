# 文件系统初始化
对于sysfs的初始化过程,内核的代码调用链条如下：
sysfs是一种kernelfs
```
start_kernel()
    vfs_caches_init()
        mnt_init()
            kernfs_init()
            sysfs_init()
```

