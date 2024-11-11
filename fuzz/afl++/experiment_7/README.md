## environment
OS: ubuntu20.04LTS
afl++: latest  
VLC: 3.0.7.1

## 部分插桩
[官方文档](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.instrument_list.md)
当我们在测试大型项目的时候,可能因为功能的多样性导致模糊测试效率十分低下，从而在不断变异升级模糊测试的过程中反而导致产生许多afl++认为有趣的变异但对于正在测试的目的相差甚远，因此这里有一种部分插桩的方法可以用来将覆盖率的记录和返回限制在几个你所指定的程序当中

这里进行部分程序插桩的方法主要是设置环境变量白名单`AFL_LLVM_ALLOWLIST`或设置黑名单`ALF_LLVM_DENYLIST`
格式如下：
```txt
project/
project/feature_a/a1.cpp
project/feature_a/a2.cpp
project/feature_b/b1.cpp
project/feature_b/b2.cpp
```
而这个部分插桩也不仅限于文件，同样可以设置函数极的插桩，格式如下：
```txt
src: *malloc.c
fun: MallocFoo         
```

## 编译VLC
先设置环境变量
```sh
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_USE_ASAN=1
export CC=afl-clang-lto
```





