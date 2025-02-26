本仓库主要是浅浅学习一下Iot的相关基础知识

# 环境准备

1. 首先安装固件提取/分析工具binwalk
2. 安装sasquatch
3. 安装交叉编译环境buildroot, 记得到target arch里面选择mipsel (MIPS little endia)

# 程序编译
在buildroot的目录下`output/host/bin/mipsel-linux-gcc`,使用这个gcc来编译程序


# 交叉架构运行
想要以工具的形式,可以使用例如`qemu-mipsel ./test`,但这里需要./test为静态链接程序
如果想运行动态链接程序，需要使用`sudo chroot . ./qemu-mipsel-static ./test`,这里的工具需要安装`qemu-user-static`包








