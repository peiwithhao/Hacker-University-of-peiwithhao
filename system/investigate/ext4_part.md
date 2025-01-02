位于`fs/ext4/file.c`
函数名`ext4_dio_write_iter()`

# 参数解析

```c
static ssize_t ext4_dio_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	handle_t *handle;
    ...
```

存在两个参数： iocb， from


## struct kiocb
结构体内容：

```c
struct kiocb {
	struct file		*ki_filp;   
	loff_t			ki_pos;
	void (*ki_complete)(struct kiocb *iocb, long ret);
	void			*private;
	int			ki_flags;
	u16			ki_ioprio; /* See linux/ioprio.h */
	union {
		/*
		 * Only used for async buffered reads, where it denotes the
		 * page waitqueue associated with completing the read. Valid
		 * IFF IOCB_WAITQ is set.
		 */
		struct wait_page_queue	*ki_waitq;
		/*
		 * Can be used for O_DIRECT IO, where the completion handling
		 * is punted back to the issuer of the IO. May only be set
		 * if IOCB_DIO_CALLER_COMP is set by the issuer, and the issuer
		 * must then check for presence of this handler when ki_complete
		 * is invoked. The data passed in to this handler must be
		 * assigned to ->private when dio_complete is assigned.
		 */
		ssize_t (*dio_complete)(void *data);
	};
};
```

+ `ki_filp`: 打开的文件
+ `ki_pos`: 数据偏移
+ `ki_complete`: IO完成回调函数

## struct iov_iter
```c
struct kvec {
	void *iov_base; /* and that should *never* hold a userland pointer */
	size_t iov_len;
};
struct iov_iter {
	u8 iter_type;
	bool copy_mc;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				struct xarray *xarray;
				void __user *ubuf;
			};
			size_t count;
		};
	};
	union {
		unsigned long nr_segs;
		loff_t xarray_start;
	};
};
```
一种迭代器，
+ `iov_offset`: 第一个iovec中数据的起始偏移
+ `nr_segs`: iovec的数量
+ `count`: 数据大小

# 调用者

```c
const struct file_operations ext4_file_operations = {
    ...
	.write_iter	= ext4_file_write_iter,
    ...
};



static ssize_t
ext4_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
    ...

#ifdef CONFIG_FS_DAX
    ...
#endif
	if (iocb->ki_flags & IOCB_DIRECT)
		return ext4_dio_write_iter(iocb, from);
    ...
}
```
`ext4_file_write_iter()`将在在`iocb->ki_flags`设置了`IOCB_DIRECT`标识之后将会调用该函数
而该函数为ext4文件系统默认调用的`write_iter`回调函数

# 函数主体流程
```c

static ssize_t ext4_dio_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	handle_t *handle;
	struct inode *inode = file_inode(iocb->ki_filp);
	loff_t offset = iocb->ki_pos;
	size_t count = iov_iter_count(from);
	const struct iomap_ops *iomap_ops = &ext4_iomap_ops;
	bool extend = false, unwritten = false;
	bool ilock_shared = true;
	int dio_flags = 0;
    ...
```
1. 这里可以看到首先是调用`file_inode(iocb->ki_filp)`来获取当前打开文件`struct file`所指向的inode
2. 获取当前写入的文件内容偏移
3. 调用`iov_iter_count(from)`,从`iov_iter`迭代器当中获取iovec的数量

然后执行下一步

```c
	/*
	 * Quick check here without any i_rwsem lock to see if it is extending
	 * IO. A more reliable check is done in ext4_dio_write_checks() with
	 * proper locking in place.
	 */
	if (offset + count > i_size_read(inode))
		ilock_shared = false;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (ilock_shared) {
			if (!inode_trylock_shared(inode))
				return -EAGAIN;
		} else {
			if (!inode_trylock(inode))
				return -EAGAIN;
		}
	} else {
		if (ilock_shared)
			inode_lock_shared(inode);
		else
			inode_lock(inode);
	}
```
进行安全性检查,这次快速检查没有使用读写同步锁：
1. 检查偏移加上数据大小是否大于`inode->i_size` ,如果大于的话说明要进行扩展,因此将`ilock_shared = false`,表示后面的操作需要独占锁
2. 查看`iocb->ki_flags`是否标识了`IOCB_NOWAIT`,如果设置了表示调用者希望非阻塞的获取锁
3. 在非阻塞的获取锁的过程中，如果判断`ilock_shared`为真，则尝试获取共享锁，否则获取独占锁
4. 在阻塞的获取锁过程中，类型同上述一致，只不过如果获取不到锁将会使得自身阻塞

紧接着下面的代码:

```c
	/* Fallback to buffered I/O if the inode does not support direct I/O. */
	if (!ext4_should_use_dio(iocb, from)) {
		if (ilock_shared)
			inode_unlock_shared(inode);
		else
			inode_unlock(inode);
		return ext4_buffered_write_iter(iocb, from);
	}
```
这里的解释已经很明了，如果inode不支持直接I/O,则回退到缓冲I/O,当然记得解锁
如果支持DIO,则进行下面的代码:
```c
	/*
	 * Prevent inline data from being created since we are going to allocate
	 * blocks for DIO. We know the inode does not currently have inline data
	 * because ext4_should_use_dio() checked for it, but we have to clear
	 * the state flag before the write checks because a lock cycle could
	 * introduce races with other writers.
	 */
	ext4_clear_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);

	ret = ext4_dio_write_checks(iocb, from, &ilock_shared, &extend,
				    &unwritten, &dio_flags);
```

这里清空了inode的状态，并且进行了下面的检查，
这个检查是查看是否需要独特的inode锁，
如果需要则释放共享锁再来获取这个独特锁

```c
	offset = iocb->ki_pos;
	count = ret;

	if (extend) {
		handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out;
		}

		ret = ext4_orphan_add(handle, inode);
		if (ret) {
			ext4_journal_stop(handle);
			goto out;
		}

		ext4_journal_stop(handle);
	}

	if (ilock_shared && !unwritten)
		iomap_ops = &ext4_iomap_overwrite_ops;
	ret = iomap_dio_rw(iocb, from, iomap_ops, &ext4_dio_write_ops,
			   dio_flags, NULL, 0);
	if (ret == -ENOTBLK)
		ret = 0;
	if (extend) {
		/*
		 * We always perform extending DIO write synchronously so by
		 * now the IO is completed and ext4_handle_inode_extension()
		 * was called. Cleanup the inode in case of error or race with
		 * writeback of delalloc blocks.
		 */
		WARN_ON_ONCE(ret == -EIOCBQUEUED);
		ext4_inode_extension_cleanup(inode, ret);
	}
```
这个部分首先进行如下的操作:
1. 设置局部变量
2. 判断extend,这个标识默认为false,在上面的`ext4_dio_write_checks`中进行判断是否为`extend I/O`
3. 如果是扩展I/O,则启动一个日志事件,事件类型为`EXT4_HT_INODE`
4. 然后将该inode添加到孤儿列表当中,这个`ext4_orphan_add` 函数在 EXT4 文件系统中扮演着重要的角色，
确保在进行 I/O 操作时，能够有效管理和跟踪那些可能导致文件系统不一致的 inode。
通过将这些 inode添加到孤儿列表中，
文件系统能够在发生故障时进行有效的恢复，维护数据的完整性和一致性。
5. 在上面的内容过后，会调用`iomap_dio_rw`进行写入,这个函数是`__io_map_dio_rw`的wrapper,下面单独解释该函数

## __io_map_dio_rw
该函数首先是为直接IO分配内存
```c
struct iomap_dio *
__iomap_dio_rw(struct kiocb *iocb, struct iov_iter *iter,
		const struct iomap_ops *ops, const struct iomap_dio_ops *dops,
		unsigned int dio_flags, void *private, size_t done_before)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct iomap_iter iomi = {
		.inode		= inode,
		.pos		= iocb->ki_pos,
		.len		= iov_iter_count(iter),
		.flags		= IOMAP_DIRECT,
		.private	= private,
	};
...

	dio = kmalloc(sizeof(*dio), GFP_KERNEL);
...
```

后面进行处理读操作，这一部分进行跳过，因为这里是写操作的分析
```c

	if (iov_iter_rw(iter) == READ) {
        ...
	} else {
		iomi.flags |= IOMAP_WRITE;
		dio->flags |= IOMAP_DIO_WRITE;
        ...
		/*
		 * Try to invalidate cache pages for the range we are writing.
		 * If this invalidation fails, let the caller fall back to
		 * buffered I/O.
		 */
		ret = kiocb_invalidate_pages(iocb, iomi.len);
		if (ret) {
			if (ret != -EAGAIN) {
				trace_iomap_dio_invalidate_fail(inode, iomi.pos,
								iomi.len);
				ret = -ENOTBLK;
			}
			goto out_free_dio;
		}

		if (!wait_for_completion && !inode->i_sb->s_dio_done_wq) {
			ret = sb_init_dio_done_wq(inode->i_sb);
			if (ret < 0)
				goto out_free_dio;
		}
	}
```
写操作这里的if-else分支主要是进行一些写操作flags的写入,然后紧接着下面的代码来进行写入

```c
	inode_dio_begin(inode);

	blk_start_plug(&plug);
	while ((ret = iomap_iter(&iomi, ops)) > 0) {
		iomi.processed = iomap_dio_iter(&iomi, dio);

		/*
		 * We can only poll for single bio I/Os.
		 */
		iocb->ki_flags &= ~IOCB_HIPRI;
	}
```

这里首先调用了`inode_dio_begin()`函数

### iomap_iter()
传递的参数为`iomap_iter`还有`iomap_ops`
这里主要的功能是处理逻辑块和物理块之间的映射，并将其保存在`iomap`结构体当中

```c
int iomap_iter(struct iomap_iter *iter, const struct iomap_ops *ops)
{
	int ret;

	if (iter->iomap.length && ops->iomap_end) {
		ret = ops->iomap_end(iter->inode, iter->pos, iomap_length(iter),
				iter->processed > 0 ? iter->processed : 0,
				iter->flags, &iter->iomap);
		if (ret < 0 && !iter->processed)
			return ret;
	}

	trace_iomap_iter(iter, ops, _RET_IP_);
	ret = iomap_iter_advance(iter);
	if (ret <= 0)
		return ret;

	ret = ops->iomap_begin(iter->inode, iter->pos, iter->len, iter->flags,
			       &iter->iomap, &iter->srcmap);
	if (ret < 0)
		return ret;
	iomap_iter_done(iter);
	return 1;
}
```
这里的`ops->iomap_begin`为之前传入的全局变量，为`ext4_iomap_begin`函数，end类似
在`ext4_iomap_begin()`函数的过程中，就会给`iomap_iter->iomap`赋值，这里的内容就是逻辑块和物理块的映射

### iomap_dio_iter
该函数进行了真正的io处理






