<!--toc:start-->
- [0. sysfs内容](#0-sysfs内容)
- [1.sysfs文件系统注册](#1sysfs文件系统注册)
- [2.sysfs的挂载](#2sysfs的挂载)
- [引用](#引用)
<!--toc:end-->

# 0. sysfs内容
在sysfs目录下有如下几种内容
```sh
❯ ls /sys
 block   bus   class   dev   devices   firmware   fs   hypervisor   kernel   module   power
```
1. block: 指示系统中所有的块设备,现在已经迁移到`/sys/class/block`,旧的接口作为向后兼容存在
    ```sh
    ❯ ls /sys/block
     nvme0n1   nvme1n1
    ❯ ls /sys/class/block
     nvme0n1   nvme0n1p1   nvme0n1p2   nvme0n1p3   nvme0n1p4   nvme1n1   nvme1n1p1   nvme1n1p2   nvme1n1p3   nvme1n1p4   nvme1n1p5   nvme1n1p6
    ```
2. bus: 所有子目录都是注册好了的总线类型,每个子目录下包含两种目录`drivers, devices`,其中`devices`是总线下的所有设备，
而这些设备均为符号链接，分别真正指向`sys/devices/`下
    ```sh
    ❯ ls -l /sys/bus/memory/devices/
    lrwxrwxrwx root root 0 B Tue Dec 17 09:42:55 2024  memory0 ⇒ ../../../devices/system/memory/memory0
    lrwxrwxrwx root root 0 B Tue Dec 17 09:42:55 2024  memory1 ⇒ ../../../devices/system/memory/memory1
    ...
    ```
而`drivers`下是所有注册在这个总线上的驱动，每个`drivers`子目录下是一些可以观察和修改的`drivers`参数
3. devices: 全局设备结构体系，包含所有被发现的注册在各种总线上的各种物理设备
4. class: 包含所有注册在kernel里面的设备类型,这里是按照设备功能分类的设备模型，
每种设备都有自己特定的功能
5. firemware: 包含具有固件对象和属性的子目录
    ```sh
    ❯ ls /sys/firmware
     acpi   dmi   efi   memmap
    ```
6. fs: 最初的设计目标是描述系统中的所有文件系统，但目前只有ext4,fuse等少数文件系统支持sysfs接口，一些传统虚拟文件系统(VFS)层次控制参数仍然存放在`/proc/sys/fs`当中
7. kernel: 包含内核所有可调整参数的位置,有些内核可调整参数仍然位于sysctl`/proc/sys/kernle`接口中
8. module: 包含所有模块的信息，不论是`inline`编译的还是动态编译`.ko`文件都会出现在此目录下
9. power: 包含系统中的电源选项，可以向其中写入控制命令进行关机，重启



# 1.sysfs文件系统注册
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

# 2.sysfs的挂载
从`sys_mount`作为入口进行分析
```
SYSCALL_DEFINE5(mount, ...)
    do_mount
       path_mount 
            do_new_mount
```
接下来解析`do_new_mount`,这个函数负责创建`superblock, root_inode, root_dentry`并且初始化他们的指责,是mount系统调用实现的关键部分

首先该函数调用了`get_fs_type(fstype)`来获取`sturct file_system_type`,
此时将会到`file_systems`链条查找之前注册的`sysfs`文件系统 

```c
static int do_new_mount(struct path *path, const char *fstype, int sb_flags,
			int mnt_flags, const char *name, void *data)
{
    ...
	type = get_fs_type(fstype);
```
此时type被赋值为`sysfs_fs_type`
```c
static struct file_system_type sysfs_fs_type = {
	.name			= "sysfs",
	.init_fs_context	= sysfs_init_fs_context,
	.kill_sb		= sysfs_kill_sb,
	.fs_flags		= FS_USERNS_MOUNT,
};
```
之后通过`fs_context_for_mount()`函数来构造在本次将要使用的`struct fs_context *fc`,

```c
...
	fc = fs_context_for_mount(type, sb_flags);
	put_filesystem(type);
...
```
在这个函数中进行了下面几个部分：
1. 分配内存空间给`fs_context`
2. 进行一些初始化
3. 调用`fstype->init_fs_context`,也就是`sysfs_init_fs_context`来进行sysfs特有的`fs_context`初始化
    1. `sysfs_init_fs_context`分配`fs->fs_private`内存空间，这里的内存结构体为`struct kernfs_fs_context`
    2. 赋值`fc->ops = &sysfs_fs_context_ops`
        ```c
        static const struct fs_context_operations sysfs_fs_context_ops = {
            .free		= sysfs_fs_context_free,
            .get_tree	= sysfs_get_tree,
        };
        ```
在完成了`fs_context_for_mount`函数之后，`do_new_mount()`需要进行的是解析传递的路径名称，然后调用`vfs_get_tree`来获取`super_block`

```c
...
	if (!err)
		err = vfs_get_tree(fc);
...
```

这个函数主要是执行了`fc->ops->get_tree(fc)`,实际上是调用了`sysfs_get_tree`
紧接着调用`kernfs_get_tree(fc)`
而这个函数就是执行了创建`sb, inode , dentry`的几个部分
1. 调用`sget_fc`,紧接着调用`alloc_sb()`来分配超级快
2. 调用`kernfs_fill_super()`,这个函数里面会分配`root_ionde, root_dentry`,赋值有以下几点需要注意:
    1. `sb->s_op = &kernfs_sops`进行赋值,
    2. `sb->s_xattr = kernefs_xattr_handlers`
    3. 在`kernfs_get_inode()`函数生成`root_inode`时会赋值如下:
        1. `inode->i_op = &kernefs_iops`或`&kernfs_dir_iops`
        2. `inode_i_fops = &kernfs_dir_fops`或`&kernfs_file_fops`
    4. `sb->s_d_op = &kernfs_dops`赋值dentry的ops
```c
const struct super_operations kernfs_sops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= kernfs_evict_inode,

	.show_options	= kernfs_sop_show_options,
	.show_path	= kernfs_sop_show_path,
};
```
在这之后`do_new_mount`将会调用`do_new_mount_fc()`函数来创建挂载点然后进行链接

# 3. kobject
在挂载的过程当中似乎每看到kobject,但是他确实是实现`/sys`文件系统的重要组成部分
```c
struct kobject {
	const char		*name;
	struct list_head	entry;
	struct kobject		*parent;
	struct kset		*kset;
	const struct kobj_type	*ktype;
	struct kernfs_node	*sd; /* sysfs directory entry */
	struct kref		kref;
#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
	struct delayed_work	release;
#endif
	unsigned int state_initialized:1;
	unsigned int state_in_sysfs:1;
	unsigned int state_add_uevent_sent:1;
	unsigned int state_remove_uevent_sent:1;
	unsigned int uevent_suppress:1;
};
```
在`/sys`目录下每一个目录项均对应着一个`kobject`结构体,在创建`kobject`的时候需要指定目录名和上级kobject

而在`kobject`目录下对应存在若干文件，这些文件被称为属性文件，每个文件对应一个`kobj_attribute`结构体
```c
struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf);
	ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count);
};
```
创建`kobj_attribute`的时候需要指定文件名，用户权限，读写函数等等

当我们需要将`kobj_attribute`绑定到某个`kobject`的时候，需要使用到`attribute_group`结构体
```c
/*
 * @name: 该attribute_group name
 */
struct attribute_group {
	const char		*name;
	umode_t			(*is_visible)(struct kobject *,
					      struct attribute *, int);
	umode_t			(*is_bin_visible)(struct kobject *,
						  struct bin_attribute *, int);
	struct attribute	**attrs;
	struct bin_attribute	**bin_attrs;
};
```
而`kobj_attribute,attribute_group`的绑定形式如下：
```c
static struct kobj_attribute foo_attribute =
	__ATTR(foo, 0664, foo_show, foo_store);
static struct kobj_attribute bar_attribute =
	__ATTR(bar, 0664, bar_show, bar_store);

static struct attribute *attrs[] = {
	&foo_attribute.attr,
	&bar_attribute.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};
```
用户访问属性文件的时候需要用到上级目录`kobject`结构体中的`kobj_type`,
```c
struct kobj_type {
	void (*release)(struct kobject *kobj);
	const struct sysfs_ops *sysfs_ops;
	struct attribute **default_attrs;	/* use default_groups instead */
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations *(*child_ns_type)(struct kobject *kobj);
	const void *(*namespace)(struct kobject *kobj);
	void (*get_ownership)(struct kobject *kobj, kuid_t *uid, kgid_t *gid);
};
```
其中存在`sysfs_ops`的操作属性文件的函数，这些函数会从`default_attrs`中取出属性文件对应的attribute,
由此才能找到对应该`attribute`所属于的`kobj_attribute`,从而取出属性操作函数



# 引用
[sysfs目录解析](https://doc.embedfire.com/linux/rk356x/driver/zh/latest/linux_driver/others_sysfs.html)
[kobject解析](https://blog.csdn.net/CharmingSun/article/details/123675972)
[sysfs文件相关操作](https://blog.csdn.net/chenying126/article/details/78079942)


