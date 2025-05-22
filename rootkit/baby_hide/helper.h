#ifndef HELPER_H
#define HELPER_H
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/init_task.h>
#include <linux/list.h>

#define CODE_BUFFER 0x100
/* HOOK_MODE */
enum HOOK_MODE{
    HOOK_ONCE          = 1 << 0,
    HOOK_ETERNAL       = 1 << 1,
    HOOK_COVER_ONCE    = 1 << 2,
    HOOK_COVER_ETERNAL = 1 << 3
};


/* hook函数的上下文结构 */
struct hook_context{
    u8 orig_code[CODE_BUFFER]; //被hook函数代码，用来进行还原
    u8 hook_code[CODE_BUFFER]; //hook函数代码
    size_t shellcode_nr; 
    size_t ret;     //存放返回值
    struct pt_regs regs;    //存放hook时的regs
    size_t (* orig_func)(size_t, size_t, size_t, size_t, size_t, size_t);
    size_t (* hook_before)(struct pt_regs *);
    size_t (* hook_after)(struct pt_regs *, size_t *);
    struct list_head hook_list;     //所有hook链接在一起
    size_t hitcount;   //击中次数
    enum HOOK_MODE mode; //表示hook模式
};


extern size_t syscall_table_data[5];
extern size_t get_syscall_data;
extern size_t syscall_table_addr;

/* 全局hook列表 */
extern struct list_head system_hook_list;






size_t arbitrary_pte_write(void *dst, void *src, size_t size);
void arbitrary_cr0_write(void *dst, void *src, size_t count);
int arbitrary_remap_write(void *dst, void *src, size_t size);
void sys_call_table_finder(void);
ssize_t hookpoint_add(struct hook_context * hook_ctx, size_t orig_func, size_t hook_before, size_t hook_after, unsigned int flags);
ssize_t hookpoint_del_all(void);
/* 注册hook点 */
struct hook_context *hook_ctx_init(void);
/* 提升权限 */
void privileged_escalation(void);


#endif
