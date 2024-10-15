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

# dl_runtime_resolve
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



# 参考
[https://blog.imv1.me/2021/04/15/ret2dl_resolve/](https://blog.imv1.me/2021/04/15/ret2dl_resolve/)
