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
这里我们先来看看`sysfs_init`过程,首先创建了`kernfs_root`, 这是一个全局静态变量,这里给我的感觉有点类似于`proc`文件系统的`proc_root`,
区别就是`proc_root`已经被代码赋予了初始值，
然后

```c
int __init sysfs_init(void)
{
	int err;

    /* 初始化struct kernfs_root sysfs_root, 并创建kernfs_node与他对应 */
	sysfs_root = kernfs_create_root(NULL, KERNFS_ROOT_EXTRA_OPEN_PERM_CHECK,
					NULL);
	if (IS_ERR(sysfs_root))
		return PTR_ERR(sysfs_root);

    /* 同样是全局静态变量 */
	sysfs_root_kn = sysfs_root->kn;

    /* 注册sysfs文件系统 */
	err = register_filesystem(&sysfs_fs_type);
	if (err) {
		kernfs_destroy_root(sysfs_root);
		return err;
	}

	return 0;
}
```

这里总共做了两件事：
1. 初始化`sysfs_root, sysfs_root_kn`,为这两者分配了空间，进行了初始化
2. 将文件系统注册到全局链表`file_systems`当中

在这之后就是文件系统的挂载过程



