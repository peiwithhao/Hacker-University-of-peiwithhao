<!--toc:start-->
- [afl-cc](#afl-cc)
<!--toc:end-->

# afl-cc
首先查看main函数的整体结构
```c
/* Main entry point */
int main(int argc, char **argv, char **envp) {

    //分配struct aflcc_state
  aflcc_state_t *aflcc = malloc(sizeof(aflcc_state_t));
    //根据传递参数初始化aflcc_state
  aflcc_state_init(aflcc, (u8 *)argv[0]);
    ...

}

```





