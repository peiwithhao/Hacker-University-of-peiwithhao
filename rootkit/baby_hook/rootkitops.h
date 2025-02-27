#ifndef ROOTKITOPS_H
#define ROOTKITOPS_H
#include <linux/types.h>
#include <linux/fs.h>

#define USER_KALLSYMS 0x1111
#define SEARCH_SYSCALL 0x2222
#define SUPER_HOOK 0x3333





ssize_t pwh_rootkit_read(struct file *, char __user *, size_t, loff_t *);
ssize_t pwh_rootkit_write(struct file *, const char __user *, size_t, loff_t *);
long pwh_rootkit_ioctl(struct file *, unsigned int, unsigned long);
int pwh_rootkit_open(struct inode *, struct file *);
int pwh_rootkit_release(struct inode *, struct file *);





#endif

