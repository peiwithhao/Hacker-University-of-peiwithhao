<!--toc:start-->
- [environment](#environment)
- [Download](#download)
- [编译](#编译)
- [持久模式](#持久模式)
- [延迟初始化](#延迟初始化)
<!--toc:end-->

## environment
OS: ubuntu20.04LTS
afl++: latest  
gimp: 2.8.16

## Download
首先是环境依赖的安装
```sh
sudo apt-get install build-essential libatk1.0-dev libfontconfig1-dev libcairo2-dev libgudev-1.0-0 libdbus-1-dev libdbus-glib-1-dev libexif-dev libxfixes-dev libgtk2.0-dev python2.7-dev libpango1.0-dev libglib2.0-dev zlib1g-dev intltool libbabl-dev gegl
```
最后需要下载目标程序`gimp 2.8.16`
```sh
wget https://mirror.klaus-uwe.me/gimp/pub/gimp/v2.8/gimp-2.8.16.tar.bz2
```



## 编译

编译gimp
```sh
CC=afl-clang-lto CXX=afl-clang-lto++ PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$HOME/Fuzzing_gimp/gegl-0.2.0/ CFLAGS="-fsanitize=address" CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ./configure --disable-gtktest --disable-glibtest --disable-alsatest --disable-nls --without-libtiff --without-libjpeg --without-bzip2 --without-gs --without-libpng --without-libmng --without-libexif --without-aa --without-libxpm --without-webkit --without-librsvg --without-print --without-poppler --without-cairo-pdf --without-gvfs --without-libcurl --without-wmf --without-libjasper --without-alsa --without-gudev --disable-python --enable-gimp-console --without-mac-twain --without-script-fu --without-gudev --without-dbus --disable-mp --without-linux-input --without-xvfb-run --with-gif-compression=none --without-xmc --with-shm=none --enable-debug  --prefix="$HOME/fuzzing_gimp/gimp-2.8.16/install"
make -j$(nproc)
make install
```
但是截至目前仍然报错，所以本章就错过了fuzz阶段



## 持久模式
主要可以参考[llvm presistent mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)
这里的持久模式可以大大提高我们的速度,他的主要功能就是为了在fuzz某个目标程序时，每次执行他不要通过fork的方式来进行，而是在单个分支下进行模糊测试
使用的例子如下
```c
#include "what_you_need_for_your_target.h"

__AFL_FUZZ_INIT();

main() {

  // anything else here, e.g. command line arguments, initialization, etc.

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                        // call!

    if (len < 8) continue;  // check for a required/useful minimum input length

    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    target_function(buf, len);
    /* Reset state. e.g. libtarget_free(tmp) */

  }

  return 0;

}
```
然后我们正常编译
```sh
afl-clang-fast -o fuzz_target fuzz_target.c -lwhat_you_need_for_your_target
```
据官方所说这样一般会将速度提升至10到20倍

## 延迟初始化
在传统的fuzz模式当中，一般名为`forkserver`的程序是由我们主程序所fork出来，然后execve目标程序,之后在`main`这里停住，然后不停的fork子进程来进行fuzz
虽然这个方法抵消掉了大多数os的链接等繁琐阶段,但它并不总是有助于执行其他耗时的初始化步骤的二进制文件
因此可以在所有初始化完毕之后， 执行模糊测试之前这个区段稍稍延后一下forkserver的初始化时间段
要实现延迟初始化，我们可以在代码合适的地方添加下面的语句

```c
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```
注意这里的`#ifdev`并不是必须的，这只是在如果没有`afl-clang-fast/afl-clang-lto/afl-gcc-fast`这类编译工具时能正常使用

其中插入的代码不能包括


## 持久模式
一些库提供无状态的API，或者可以在处理不同输入文件之间重置其状态。执行此类重置后，可以重复使用单个长寿命进程来尝试多个测试用例，从而无需重复fork()调用和相关的操作系统开销。
执行下面的程序可以实现这一目标
```c
  while (__AFL_LOOP(1000)) {

    /* Read input data. */
    /* Call library code to be fuzzed. */
    /* Reset state. */

  }

  /* Exit normally. */
```
## 共享内存模式
这里是使用共享内存而不是标准输入输出接受测试数据，这又可以将模糊测试加速2倍左右
设置如下，先包含某个宏
```c
__AFL_FUZZ_INIT();
```
然后直接在`main`函数开始前，或者说如果采用了延迟初始化的forkserver模式,则写在`__AFL_INIT()`之后
```c
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
```
然后在`while(__AFL_LOOP(1000))`循环的第一行写下如下代码
```c
  int len = __AFL_FUZZ_TESTCASE_LEN;
```
这类技巧可以留在编写指定模糊进程harness的时候使用



