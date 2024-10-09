# libexif

<!--toc:start-->
- [libexif](#libexif)
  - [environment](#environment)
  - [编译libexif](#编译libexif)
  - [编译exif](#编译exif)
  - [寻找测试样例](#寻找测试样例)
  - [afl-clang-lto插桩](#afl-clang-lto插桩)
  - [fuzzing time](#fuzzing-time)
  - [后续分析](#后续分析)
<!--toc:end-->


## environment
OS: ubuntu20.04LTS
LLVM: 16
afl++: latest  
libexif: 0.6.14

## 编译libexif
编译我们的漏洞程序
```sh
export LLVM_CONFIG="llvm-config-16"
CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

## 编译exif
我们需要寻找到使用该lib库API的程序,于是便找到exif
```c
cd exif-exif-0_6_15-release/
autoreconf -fvi
./configure --enable-shared=no --prefix="$HOME/fuzzing_libexif/install/" PKG_CONFIG_PATH=$HOME/fuzzing_libexif/install/lib/pkgconfig
make
make install
```
编译过后应该调用`fuzzing_libxif/install/bin/exif`会出现下面的
```sh
Usage: exif [OPTION...] file
  -v, --version                   Display software version
  -i, --ids                       Show IDs instead of tag names
  -t, --tag=tag                   Select tag
      --ifd=IFD                   Select IFD
  -l, --list-tags                 List all EXIF tags
  -|, --show-mnote                Show contents of tag MakerNote
      --remove                    Remove tag or ifd
  -s, --show-description          Show description of tag
  -e, --extract-thumbnail         Extract thumbnail
  -r, --remove-thumbnail          Remove thumbnail
  -n, --insert-thumbnail=FILE     Insert FILE as thumbnail
  -o, --output=FILE               Write data to FILE
      --set-value=STRING          Value
  -m, --machine-readable          Output in a machine-readable (tab delimited) format
  -x, --xml-output                Output in a XML format
  -d, --debug                     Show debugging messages

Help options:
  -?, --help                      Show this help message
      --usage                     Display brief usage message
```

## 寻找测试样例
由于这个库是用来查看图片相关类容,因此我们可以将图片作为测试样例来输入
```sh
wget https://github.com/ianare/exif-samples/archive/refs/heads/master.zip
unzip master.zip
```

## afl-clang-lto插桩
首先我们需要删除我们刚刚编译后的二进制文件

```sh
rm -r $HOME/fuzzing_libexif/install
cd $HOME/fuzzing_libexif/libexif-libexif-0_6_14-release/
make clean
export LLVM_CONFIG="llvm-config-11"
CC=afl-clang-lto ./configure --enable-shared=no --prefix="$HOME/fuzzing_libexif/install/"
make
make install

cd $HOME/fuzzing_libexif/exif-exif-0_6_15-release
make clean
export LLVM_CONFIG="llvm-config-11"
CC=afl-clang-lto ./configure --enable-shared=no --prefix="$HOME/fuzzing_libexif/install/" PKG_CONFIG_PATH=$HOME/fuzzing_libexif/install/lib/pkgconfig
make
make install

```
## fuzzing time
这里选择`afl-clang-lto`而不是`afl-clang-fast`因为他是一种无碰撞的插桩,并且更快
然后开始fuzzing
```
afl-fuzz -i $HOME/fuzzing_libexif/exif-samples-master/jpg/ -o $HOME/fuzzing_libexif/out/ -s 123 -- $HOME/fuzzing_libexif/install/bin/exif @@
```

## 后续分析
我们分析out目录下的crash点,发现出现了段错误
我们使用gdb进行分析发现栈帧情况如下
```c
(gdb) bt
#0  0x000055c71598fe20 in exif_get_sshort (
    buf=0x55c83a76fa21 <error: Cannot access memory at address 0x55c83a76fa21>, 
    order=EXIF_BYTE_ORDER_INTEL)
    at /home/fuzzing_libexif/libexif-libexif-0_6_14-release/libexif/exif-utils.c:92
#1  exif_get_short (
    buf=0x55c83a76fa21 <error: Cannot access memory at address 0x55c83a76fa21>, 
    order=EXIF_BYTE_ORDER_INTEL)
    at /home/fuzzing_libexif/libexif-libexif-0_6_14-release/libexif/exif-utils.c:104
#2  exif_data_load_data (data=0x55c73a76ea10, d_orig=<optimized out>, 
    ds_orig=<optimized out>) at exif-data.c:819
#3  0x000055c715986d14 in exif_loader_get_data (loader=0x0)
    at /home/fuzzing_libexif/libexif-libexif-0_6_14-release/libexif/exif-loader.c:387
#4  main (argc=<optimized out>, argv=<optimized out>) at main.c:438
```

这里发现在exif_get_short这个函数出现了越界访问,我们重启进程在exif_data_load_data中可以看到


```c
void
exif_data_load_data (ExifData *data, const unsigned char *d_orig,
                     unsigned int ds_orig)
...
 if (offset + 6 + 2 > ds) {
                return;
        }
        n = exif_get_short (d + 6 + offset, data->priv->order);
...
```

这里的offset经过漏洞样本的调试发现为一个负数,这样可以越过上面的检查,而在这里`exif_get_short`的第一个参数为地址,因此这里就造成了越界异常,而这个漏洞已经被记录为`CVE-2012-2836`
