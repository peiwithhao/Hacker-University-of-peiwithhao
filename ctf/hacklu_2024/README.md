# gym_notes
题目给出了代码，其中`delNote`可以泄露代码段基地址
```c
void delNote() {
  printf("Function 0x%lx isn't implemented yet..\n", (void*)delNote);
}
```
