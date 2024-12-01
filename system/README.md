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




# 引用
[filesystem](qute://pdfjs/web/viewer.html?filename=tmplgnr5ptt_Linux.Virtual.Filesystem.pdf&file=&source=https://lrita.github.io/images/posts/filesystem/Linux.Virtual.Filesystem.pdf)


