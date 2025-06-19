# vhost-net
其被实现为一种驱动，用来加速虚拟化网络

环境: linux-6.3.4
源码位于`/home/peiwithhao/Kernel/kernel_source/linux-6.3.4/drivers/vhost/vhost.c`


首先该驱动被注册为一个misc设备

```c
static int __init vhost_net_init(void)
{
	if (experimental_zcopytx)
		vhost_net_enable_zcopy(VHOST_NET_VQ_TX);
	return misc_register(&vhost_net_misc);
}
module_init(vhost_net_init);
```


其中的fops如下:

```c

static const struct file_operations vhost_net_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_net_release,
	.read_iter      = vhost_net_chr_read_iter,
	.write_iter     = vhost_net_chr_write_iter,
	.poll           = vhost_net_chr_poll,
	.unlocked_ioctl = vhost_net_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.open           = vhost_net_open,
	.llseek		= noop_llseek,
};
```


`vhost_net_open()`当打开`vhost-net`模块时会进行调用
```c

	vhost_dev_init(dev, vqs, VHOST_NET_VQ_MAX,
		       UIO_MAXIOV + VHOST_NET_BATCH,
		       VHOST_NET_PKT_WEIGHT, VHOST_NET_WEIGHT, true,
		       NULL);

	vhost_poll_init(n->poll + VHOST_NET_VQ_TX, handle_tx_net, EPOLLOUT, dev);
	vhost_poll_init(n->poll + VHOST_NET_VQ_RX, handle_rx_net, EPOLLIN, dev);
```

这里会初始化poll事件，其中的第二个参数是用来进行回调
```c
static void handle_tx_net(struct vhost_work *work)
{
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_TX].work);
	handle_tx(net);
}
```


进入`vhost_poll_init()`函数会发现他是给一些virtqueue字段进行赋值
```c
/* Init poll structure */
void vhost_poll_init(struct vhost_poll *poll, vhost_work_fn_t fn,
		     __poll_t mask, struct vhost_dev *dev)
{
	init_waitqueue_func_entry(&poll->wait, vhost_poll_wakeup); 
	init_poll_funcptr(&poll->table, vhost_poll_func);
	poll->mask = mask;
	poll->dev = dev;
	poll->wqh = NULL;

	vhost_work_init(&poll->work, fn);
}
EXPORT_SYMBOL_GPL(vhost_poll_init);
```



```txt
vhost_net_open
    vhost_poll_init  //初始化poll结构体
        init_waitqueue_func_entry  //给poll的等待队列注册func
        vhost_work_init     //将传入的handle_tx/rx 指针注册到vhost_work->fn当中供后续调用
```



然而我们每一个虚拟机都会分配一个内核线程来处理网络包传递,调用`handle_tx()/handle_rx()`
而这个内核线程的创建方式在`vhost_net_ioctl(fd, VHOST_SET_OWNER, **)`当中


```c

/* Caller should have device mutex */
long vhost_dev_set_owner(struct vhost_dev *dev)
{
    ...
	if (dev->use_worker) {
		worker = kthread_create(vhost_worker, dev,
					"vhost-%d", current->pid);
		if (IS_ERR(worker)) {
			err = PTR_ERR(worker);
			goto err_worker;
		}

		dev->worker = worker;
		wake_up_process(worker); /* avoid contributing to loadavg */

		err = vhost_attach_cgroups(dev);
		if (err)
			goto err_cgroup;
	}
    ...
}
EXPORT_SYMBOL_GPL(vhost_dev_set_owner);
```

这里创建了线程就会立即唤醒，然后内核线程的函数`vhost_worker`会根据自己的调用逻辑暂停,之后就等待其他函数的唤醒

当触发`vhost_poll_queue()`函数就会调用该内核线程来处理事务

```c
void vhost_work_queue(struct vhost_dev *dev, struct vhost_work *work)
{
	if (!dev->worker)
		return;

	if (!test_and_set_bit(VHOST_WORK_QUEUED, &work->flags)) {
		/* We can only add the work to the list after we're
		 * sure it was not in the list.
		 * test_and_set_bit() implies a memory barrier.
		 */
		llist_add(&work->node, &dev->work_list);
		wake_up_process(dev->worker);
	}
}
```

线程所做的事情如下:
```c

static int vhost_worker(void *data)
{
	struct vhost_dev *dev = data;
	struct vhost_work *work, *work_next;
	struct llist_node *node;

	kthread_use_mm(dev->mm);

	for (;;) {
		/* mb paired w/ kthread_stop */
		set_current_state(TASK_INTERRUPTIBLE);

		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}

		node = llist_del_all(&dev->work_list);
		if (!node)
			schedule();

		node = llist_reverse_order(node);
		/* make sure flag is seen after deletion */
		smp_wmb();
		llist_for_each_entry_safe(work, work_next, node, node) {
			clear_bit(VHOST_WORK_QUEUED, &work->flags);
			__set_current_state(TASK_RUNNING);
			kcov_remote_start_common(dev->kcov_handle);
			work->fn(work);
			kcov_remote_stop();
			if (need_resched())
				schedule();
		}
	}
	kthread_unuse_mm(dev->mm);
	return 0;
}
```

其中`work->fn(work)`实际上根据上面的分析就是调用`handle_tx_net()/handle_rx_net()`


