#ifndef HIDDEN_H
#define HIDDEN_H
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/init_task.h>
#include <linux/string.h>
#define DIR_PATH_NR 0x30
#define FILE_PATH_NR 0x30


// static void getdents64_before_hooker(struct pt_regs *);
// static void getdents64_after_hooker(struct pt_regs *);

ssize_t dir_hidden_weak(char *);
ssize_t file_hidden(char *);

#endif
