# 开始AFL++
至于AFL++的下载,这里建议就直接`docker pull aflplusplus/aflplusplus`,

## 测试C代码

首先我们需要使用`afl-cc`或`afl-clang-fast`进行编译
`afl-clang-fast -AFL_HARDEN=1 vulnerable.c -o vulnerable`
这里是选择更好的插桩方式,而使用afl-cc会自动选择更合适的编译器

+ AFL_HARDEN = 1表示会让下游编译器自动化代码加固,使得能更容易检测简单的内存bug
其他的环境变量设置可以参阅
[https://aflplus.plus/docs/env_variables](https://aflplus.plus/docs/env_variables)
然后接下来的步骤需要创建输入输出文件夹
```shell
$ mkdir input out
$ echo 1 > input/1
$ echo u fdas@ > input/2
```
然后就是开始fuzz过程

```shell
$ afl-fuzz -i input/ -o out/ ./vulnerable
```


# Reference
[https://github.com/mykter/afl-training](https://github.com/mykter/afl-training)
[https://ghcr.io/mykter/fuzz-training](https://ghcr.io/mykter/fuzz-training)

