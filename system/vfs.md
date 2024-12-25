# VFS
目的在于提供一个抽象层来供用户使用不同类型的文件系统

## 超级块
一个超级块内部保存的信息包括了设备标识符，块的单位，文件系统类型等等，一个超级块在内存里面就表示一个文件系统
```c
struct super_block {
	struct list_head	s_list;		/* Keep this first */
	dev_t			s_dev;		/* search index; _not_ kdev_t */
	unsigned char		s_blocksize_bits;
	unsigned long		s_blocksize;
	loff_t			s_maxbytes;	/* Max file size */
	struct file_system_type	*s_type;
	const struct super_operations	*s_op;
	const struct dquot_operations	*dq_op;
	const struct quotactl_ops	*s_qcop;
	const struct export_operations *s_export_op;
	unsigned long		s_flags;
	unsigned long		s_iflags;	/* internal SB_I_* flags */
	unsigned long		s_magic;
	struct dentry		*s_root;
    ...
}

```
而该sb的分配是由函数`alloc_super()`来从硬盘加载文件系统超级快
```c
/**
 *	alloc_super	-	create new superblock
 *	@type:	filesystem type superblock should belong to
 *	@flags: the mount flags
 *	@user_ns: User namespace for the super_block
 *
 *	Allocates and initializes a new &struct super_block.  alloc_super()
 *	returns a pointer new superblock or %NULL if allocation had failed.
 */
static struct super_block *alloc_super(struct file_system_type *type, int flags,
				       struct user_namespace *user_ns)
{
	struct super_block *s = kzalloc(sizeof(struct super_block),  GFP_USER);
	static const struct super_operations default_op;
    ...
}

```
而关于该超级块的操作函数结构体类型为`struct super_operations`

```c
struct super_operations {
   	struct inode *(*alloc_inode)(struct super_block *sb);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);

   	void (*dirty_inode) (struct inode *, int flags);
	int (*write_inode) (struct inode *, struct writeback_control *wbc);
	int (*drop_inode) (struct inode *);
	void (*evict_inode) (struct inode *);
	void (*put_super) (struct super_block *);
	int (*sync_fs)(struct super_block *sb, int wait);
	int (*freeze_super) (struct super_block *);
	int (*freeze_fs) (struct super_block *);
	int (*thaw_super) (struct super_block *);
	int (*unfreeze_fs) (struct super_block *);
	int (*statfs) (struct dentry *, struct kstatfs *);
	int (*remount_fs) (struct super_block *, int *, char *);
	void (*umount_begin) (struct super_block *);

	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	int (*show_stats)(struct seq_file *, struct dentry *);
#ifdef CONFIG_QUOTA
	ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
	struct dquot **(*get_dquots)(struct inode *);
#endif
	long (*nr_cached_objects)(struct super_block *,
				  struct shrink_control *);
	long (*free_cached_objects)(struct super_block *,
				    struct shrink_control *);
};
```
这里面的操作函数表包含了对于inode的一系列功能函数,同时包含释放,更新`super_block`的功能


## inode
inode包含了内核在访问文件对象所需要的一切信息
```c
/*
 * Keep mostly read-only and often accessed (especially for
 * the RCU path lookup and 'stat' data) fields at the beginning
 * of the 'struct inode'
 */
struct inode {
	umode_t			i_mode;
	unsigned short		i_opflags;
	kuid_t			i_uid;
	kgid_t			i_gid;
	unsigned int		i_flags;

    ...

	void			*i_private; /* fs or device private pointer */
} __randomize_layout;
```
这样一个inode就代表了文件系统当中的一个文件,字段内容则包含了使用者uid等等信息

这里包含两个函数结构指针`i_op`和`i_fop`,一个用来特定于inode操作，另一个则提供了文件操作

然后操作他的相关函数则保存在`inode_operations`当中
```c
struct inode_operations {
	struct dentry * (*lookup) (struct inode *,struct dentry *, unsigned int);
	const char * (*get_link) (struct dentry *, struct inode *, struct delayed_call *);
	int (*permission) (struct user_namespace *, struct inode *, int);
	struct posix_acl * (*get_acl)(struct inode *, int, bool);

	int (*readlink) (struct dentry *, char __user *,int);

	int (*create) (struct user_namespace *, struct inode *,struct dentry *,
		       umode_t, bool);
	int (*link) (struct dentry *,struct inode *,struct dentry *);
	int (*unlink) (struct inode *,struct dentry *);
	int (*symlink) (struct user_namespace *, struct inode *,struct dentry *,
			const char *);
	int (*mkdir) (struct user_namespace *, struct inode *,struct dentry *,
		      umode_t);
	int (*rmdir) (struct inode *,struct dentry *);
	int (*mknod) (struct user_namespace *, struct inode *,struct dentry *,
		      umode_t,dev_t);
	int (*rename) (struct user_namespace *, struct inode *, struct dentry *,
			struct inode *, struct dentry *, unsigned int);
	int (*setattr) (struct user_namespace *, struct dentry *,
			struct iattr *);
	int (*getattr) (struct user_namespace *, const struct path *,
			struct kstat *, u32, unsigned int);
	ssize_t (*listxattr) (struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64 start,
		      u64 len);
	int (*update_time)(struct inode *, struct timespec64 *, int);
	int (*atomic_open)(struct inode *, struct dentry *,
			   struct file *, unsigned open_flag,
			   umode_t create_mode);
	int (*tmpfile) (struct user_namespace *, struct inode *,
			struct dentry *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode *,
		       struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *mnt_userns,
			    struct dentry *dentry, struct fileattr *fa);
	int (*fileattr_get)(struct dentry *dentry, struct fileattr *fa);
} ____cacheline_aligned;
```
里面包含了inode关于dentry的一些操作，比如说`create()`函数就是用来根据dentry来创建inode

## dentry
在路径解析的过程当中需要用到这个结构体，该结构体可以是目录，也可以是普通文件，例如`/bin/sh`中`/, bin, sh`均拥有一个dentry
```c
struct dentry {
	/* RCU lookup touched fields */
	unsigned int d_flags;		/* protected by d_lock */
	seqcount_spinlock_t d_seq;	/* per dentry seqlock */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/* parent directory */
	struct qstr d_name;
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	/* Ref lookup also touches following */
	struct lockref d_lockref;	/* per-dentry lock and refcount */
	const struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	unsigned long d_time;		/* used by d_revalidate */
	void *d_fsdata;			/* fs-specific data */

	union {
		struct list_head d_lru;		/* LRU list */
		wait_queue_head_t *d_wait;	/* in-lookup ones only */
	};
	struct list_head d_child;	/* child of parent list */
	struct list_head d_subdirs;	/* our children */
	/*
	 * d_alias and d_rcu can share memory
	 */
	union {
		struct hlist_node d_alias;	/* inode alias list */
		struct hlist_bl_node d_in_lookup_hash;	/* only for in-lookup ones */
	 	struct rcu_head d_rcu;
	} d_u;
} __randomize_layout;
```
和上面的`super_block, inode`所不同的是，dentry不会存在于磁盘上，他只是用来临时创建出来方便遍历文件所得的
而一个dentry有三种状态: 被使用， 未被使用，负状态
+ 在被使用状态下，证明`dentry.d_ionde`此时是指向属于自己的inode的,并且`d_count`为正值，这也表明VFS正在使用它并且有多个使用者在使用，所以不能被弃用
+ 在未被使用状态下同样`dentry.d_inode`指向一个inode,但是`d_count`为0,
这表示没有使用者，此时该目录项不会过早的销毁，以便于加速文件路径的寻找，但如果此时触发内存回收的话可以将其释放掉
+ 在负状态下，`dentry.d_inode`为NULL，这里说明inode已经消除，此时目录项仍然保留,但如果此时触发内存回收的话可以将其释放掉

而要操作dentry,同样提供了`dentry_operations`结构体
```c
struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *,
			unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char *(*d_dname)(struct dentry *, char *, int);
	struct vfsmount *(*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry *(*d_real)(struct dentry *, const struct inode *);
} ____cacheline_aligned;
```




## dcache
文件中的一个inode，可能会有多个dentry与其对应，因此需要一个字段将对应的值保存起来，这个字段就是`inode.i_dentry`,这个双链表链接了所有与该inode关联的dentry结构体

## file
多个进程可打开同一个文件，所以可能存在一个文件对应多个`struct file`,而`file->f_dentry`则指向该文件所对应的`dentry`,而从此也可以找到对应的`inode`




# Linux 伪文件系统
仅存在于内存当中的文件系统,在runc初始化容器过程中将为容器所在的`mount namespace`挂载procfs和sysfs

## procfs
提供一种访问内核数据结构和运行时系统信息的方式，
可以通过查看该文件系统下各类文件来访问系统内存的使用情况和统计信息，
其输出的动作由内核中的各个伪文件所绑定的回调函数完成，对应内核回调函数可对文件读取进程所属的命名空间进行检查，
从而输出对应命名空间的系统信息从而实现伪文件的容器化隔离

而procfs同样包含一类`ctl_table`信息,对应`/proc/sys`目录下的文件，每个文件内容一般对应一个内核参数全局变量
文件内容可以通过sysctl内核参数修改工具来更改

## sysfs
该文件系统主要用于呈现系统设备和驱动程序信息,
使得用户和应用程序可以方便的访问和管理系统中的硬件设备。
sysfs的核心为kobject结构体,其中包含内核对象的属性，而Kobject可用于管理设备、驱动程序、总线、类别等各种内核对象
用户空间可以通过sysfs文件系统接口读取和修改kobject属性值，也可以通过sysfs中的文件触发特定操作。
sysfs提供两种判断文件是否可见：
1. 属性组文件所在的kobject的namespace
2. 属性组文件的`is_visible`机制，该机制用于确定该属性组文件是否对用户空间可见

## 源码解读
就仅拿proc伪文件系统当作例子，在内核启动阶段会默认使用该fs
源码调用链首先从`start_kernel()`开始,
`start_kernel()`是用来进行一些内核初始化工作，例如初始化`cgroup, page_alloc`
```c
asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
	char *command_line;
	char *after_dashes;
    ...
    proc_root_init();
    ...
}
```
在`proc_root_init()`函数中所进行的操作分为以下几个步骤：
```link
proc_root_init()
    proc_init_kmemcache()    //创建proc相关的一些专有缓存池
    proc_sys_init()          //初始化/proc/sys/*, 这里面是sysctl所使用到的部分
    register_filesystem(&proc_fs_type) //向全局文件系统列表中注册,保存到file_system的全局链表中
    
```

其中`proc_fs_type`为一个全局变量
```c
static struct file_system_type proc_fs_type = {
	.name			= "proc",
	.init_fs_context	= proc_init_fs_context,
	.parameters		= proc_fs_parameters,
	.kill_sb		= proc_kill_sb,
	.fs_flags		= FS_USERNS_MOUNT | FS_DISALLOW_NOTIFY_PERM,
};
```
在这之后用户就可以通过调用`mount -t proc /dev/null /proc`挂载文件系统

这里讲解一下mount的大致步骤：
首先就是`__x64_sys_mount()`函数
```c
SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
    ...
	ret = do_mount(kernel_dev, dir_name, kernel_type, flags, options);
    ...
}
```
这里只关注主要的部分，这里的`do_mount`是进行mount的主体部分

```c

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __randomize_layout;

long do_mount(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	struct path path;
    ...
	ret = path_mount(dev_name, &path, type_page, flags, data_page);
	path_put(&path);
	return ret;
}
```
这里的`vfsmount`表示了当前用户传入的挂载点信息,
然后同`struct dentry`作为`sturct path`结构体传入给下一个函数`path_mount()`

```c
int path_mount(const char *dev_name, struct path *path,
		const char *type_page, unsigned long flags, void *data_page)
{
    ...
	return do_new_mount(path, type_page, sb_flags, mnt_flags, dev_name,
			    data_page);
}
```
省略的代码是一些flags的设置我们暂时按下不表,主要集中在`do_new_mount()`

```c
static int do_new_mount(struct path *path, const char *fstype, int sb_flags,
			int mnt_flags, const char *name, void *data)
{
	struct file_system_type *type;
	struct fs_context *fc;
	const char *subtype = NULL;
	int err = 0;

	if (!fstype)
		return -EINVAL;

	type = get_fs_type(fstype); //获取上面在初始化文件系统的时候连接到file_system的类型变量
	if (!type)
		return -ENODEV;

	if (type->fs_flags & FS_HAS_SUBTYPE) {
		subtype = strchr(fstype, '.');
		if (subtype) {
			subtype++;
			if (!*subtype) {
				put_filesystem(type);
				return -EINVAL;
			}
		}
	}

	fc = fs_context_for_mount(type, sb_flags);  //这里就是调用fs_type->init_fs_context来构造fs_context
	put_filesystem(type);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	if (subtype)
		err = vfs_parse_fs_string(fc, "subtype",
					  subtype, strlen(subtype));
	if (!err && name)
		err = vfs_parse_fs_string(fc, "source", name, strlen(name));
	if (!err)
		err = parse_monolithic_mount_data(fc, data);
	if (!err && !mount_capable(fc))
		err = -EPERM;
	if (!err)
		err = vfs_get_tree(fc);
	if (!err)
		err = do_new_mount_fc(fc, path, mnt_flags);

	put_fs_context(fc);
	return err;
}
```
上面函数所做的东西如下：
1. 调用`get_fs_type(fstype)`来获取`struct file_system_type proc_fs_type`;
2. 调用`fs_context_for_mount(type, sb_flags)`来分配`fs_context`,
并且内容包括`ops`等被`proc_init_fs_context()`函数所初始化,赋予`fc->ops = proc_fs_context_ops`,内容如下:
```c
static const struct fs_context_operations proc_fs_context_ops = {
	.free		= proc_fs_context_free,
	.parse_param	= proc_parse_param,
	.get_tree	= proc_get_tree,
	.reconfigure	= proc_reconfigure,
};
```
3. 中间省略一部分检查，假设我们均通过，调用`vfs_get_tree(fc)`,
   该函数的功能就是获取可以mount的root,在这个函数中首先需要调用`fc->ops->get_tree(c)`,在这里就是`proc_get_tree(fc)`函数,在下面的步骤讲解
    1. 这个函数是`get_tree_nodev(fc, proc_fill_super)`的wrapper
    2. 上面的函数又是`vfs_get_super(fc, vfs_get_independent_super, fill_super)`的wrapper
    3. 调用`sget_fc()`函数来创建一个新的匿名`super_block`, 这里创建完sb后会将其链接到内核全局变量`super_blocks`当中
    4. 调用`fill_super`,也就是`proc_fill_super()`来填充这个`super_block`,例如`s_ops = proc_sops`等等,注意后来所有的`alloc_inode`类的函数都是从里面调用，~~inode也都换成了`struct proc_inode`~~,说错了应该是返回的仍然是普通inode,只不过`proc_inode`里面包含`inode`

    5. 上面的函数除了填充一些标志位， 还需要调用`proc_get_inode(s, &proc_root)`,来获取`root_inode`,这个`&proc_root`是一个全局变量`struct proc_dir_entry proc_root`,代表了`/proc`的`dentry`
    6. 最后将`fc->root = dget(sb->s_root)`,也就是指向了刚刚创建的`root_inode`所对应的`dentry`
4. 调用`do_new_mount_fc()`,这个函数主要是使用一个superblock来创建新的mount结构体
    1. 调用`vfs_create_mount()`来创建`vfsmount`,在过程中会赋值`mnt->mnt_mountpoint = mnt->mnt.mnt_root`,也就是`root_inode`所对应的dentry
    2. 将该挂载点连接到双链表， `mnt->mnt.mnt_sb->s_mounts`当中
    3. 调用`do_add_mount()`函数将这个mount添加到命名空间的`mount tree`当中，

上面存在没讲详细的一点，那就是在调用`proc_fill_super()`函数过程中，在填充了`superblock`之后，还需要获取`root_inode`,这个时候是使用`proc_get_inode()`函数，在这个函数当中不止调用了`sb->alloc_inode`,同时还对传回来的inode做出了一些初始化的工作,例如：
`inode->i_fop = &proc_reg_file_ops`

```c
/*
 * This is the root "inode" in the /proc tree..
 */
struct proc_dir_entry proc_root = {
	.low_ino	= PROC_ROOT_INO, 
	.namelen	= 5, 
	.mode		= S_IFDIR | S_IRUGO | S_IXUGO, 
	.nlink		= 2, 
	.refcnt		= REFCOUNT_INIT(1),
	.proc_iops	= &proc_root_inode_operations, 
	.proc_dir_ops	= &proc_root_operations,
	.parent		= &proc_root,
	.subdir		= RB_ROOT,
	.name		= "/proc",
};
```
最后就是`do_new_mount_fc()`这个函数做了一些关于挂载点的操作





## 总结
最后总结一下任何文件系统的初始化过程：
1. 注册文件系统，最主要的那个是`struct file_system_type`,此时仅仅是将该结构体链接到全局链表
2. 挂载文件系统，这个步骤需要到全局链表中寻找到文件系统类型`struct file_system_type`,然后调用其中的函数来新创建`super_block`,链接到全局链表,然后需要创建`root_inode,dentry`，然后将dentry中的相应字段指向`superblock`,然后创建挂载点`struct mount`并且链接到当前命名空间链表
3. 这里注意当我们想要挂载一个文件系统，首先将挂载的dentry标记为已挂载,然后创建新的挂载文件系统的根`dentry`再创建`mount, vfsmount`来指向该根dentry,然后将mount链接全局链表和连接父mount,之后当我们遍历文件系统，看到某个`dentry`为挂载点，则通过hash搜索找到所挂载文件系统的`mount`,然后顺势找到文件系统的根dentry
4. 最后当打开文件的时候，首先是从根`dentry`开始查找，然后找到目的文件的`dentry`和`inode`,然后填充创建的`struct file`数据结构并且返回

这里记录一下`/proc/<pid>`文件夹的创建是在`fork`系统调用过程当中，核心函数为`proc_pid_instantiate()`



# 引用
[filesystem](qute://pdfjs/web/viewer.html?filename=tmplgnr5ptt_Linux.Virtual.Filesystem.pdf&file=&source=https://lrita.github.io/images/posts/filesystem/Linux.Virtual.Filesystem.pdf)
[mountpoint](https://www.bilibili.com/opus/677932331134091304)

