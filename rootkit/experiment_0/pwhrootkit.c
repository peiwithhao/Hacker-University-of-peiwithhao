#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/printk.h>



static int __init pwh_init(void){
    /* 注册字符设备 */
    printk(KERN_INFO "[peiwithhao rootkit] Start to register ch-device...");
    return 0;
}

static void __exit pwh_exit(void){
    printk(KERN_INFO "Peiwithhao's baby rootkit out :(\n");
}


module_init(pwh_init);
module_exit(pwh_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("peiwithhao");
