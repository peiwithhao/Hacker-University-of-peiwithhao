# 构建busybox
下载源码[https://busybox.net/downloads/](https://busybox.net/downloads/)

然后进入目录使用默认初始配置`make defconfig`

然后使用`make menuconfig`来进行图像化的配制

这里注意不要选择Settings->Build static binary(no shared libs)
其他几乎默认即可

然后编译

`make && make install`

