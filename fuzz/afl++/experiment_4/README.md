本次实验将fuzz tcpdump包分析器

## environment
OS: ubuntu20.04LTS
gcc: 8.4.0
gcov: 8.4.0
afl++: latest  
libtiff:4.0.4
lcov:1.14

## libtiff 下载
```sh
wget https://download.osgeo.org/libtiff/tiff-4.0.4.tar.gz
```
解包可以发现其中有用来测试的例子和代码,在`test/, tools/`包下

## libtiff 编译
由于本次是需要使用到`gcov, lcov`,所以编译器我们需要选择`afl-gcc`，因为gcov是内置在gcc里面
而lcov是一种覆盖率网页式显示的前端工具
```sh
export CC=afl-gcc
export CXX=afl-g++
export CFLAGS="--coverage"  # 收集覆盖率
export LDFLAGS="--coverage"
export AFL_USE_ASAN = 1     # 设置Asan
./configure --prefix=$HOME/fuzzing_libtiff/install/ --disable-shared    
make 
make install
```

## lcov设置
```sh
$ lcov --zerocounters --directory ./      #重置计数器
$ lcov --capture --initial --directory ./ --output-file app.info #返回基线覆盖率数据文件，其中包含每个检测线的覆盖率
$ afl-fuzz .....   #需要保证命令执行在当前目录下
$ lcov --no-checksum --directory ./ --capture --output-file app2.info #将当前覆盖状态保存到app2.info当中
```

## fuzzing 阶段
```sh
afl-fuzz -m none -s 123 -i ../in -o ../out/ -- $HOME/fuzzing_libtiff/install/bin/tiffinfo -D -j -c -r -s -w @@
```
这次比之前tcpdump的fuzz快了不止一点点，即使使用的是`afl-gcc`
当fuzz结束后覆盖率保存到指定`*.info`下，然后使用下面命令生成html报告
```sh
genhtml --highlight --legend -output-directory ./html-coverage/ ./app2.info
```
然后我们就能够通过查看`./html-coverage/index.html`来了解整轮程序的覆盖率信息





