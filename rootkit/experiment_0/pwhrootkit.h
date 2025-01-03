#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>

#define DEVICE_NAME "pwhrootkit"
#define CLASS_NAME "pwhrootkit"

static int major_num;
static int erro_code;
static struct class *module_class;
static struct device *module_device;

static ssize_t pwh_rootkit_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t pwh_rootkit_write(struct file *, const char __user *, size_t, loff_t *);
static long pwh_rootkit_ioctl(struct file *, unsigned int, unsigned long);
static int pwh_rootkit_open(struct inode *, struct file *);
static int pwh_rootkit_release(struct inode *, struct file *);

static struct file_operations pwh_rootkit_fops = {
    .owner = THIS_MODULE,   //这里是内核中实现的一个宏,标示出编译阶段生成的与当前内核模块关联的struct module结构体的地址
    .open = pwh_rootkit_open,
    .read = pwh_rootkit_read,
    .write = pwh_rootkit_write,
    .release = pwh_rootkit_release, 
    .unlocked_ioctl = pwh_rootkit_ioctl,
};




