# 编译
仍然是make项目,直接`make menuconfig`来配置
这里buildroot提供了很多配置功能,就比如设置主机名/root密码等等,他甚至能有game的选项:)
但是他有时候干的事情太多了,就比如默认配置会自动下载linux和uboot的官方源码,里面可能缺少很多驱动文件,因此我们需要取消选择下面这两个选项
`Kernel->Linux Kernel, Bootloaders->U-Boot`

然后等我们选择好配置之后,就直接开始编译`sudo make`,这里据说不能使用`-jn`来指定多核编译

最终存储是放在`output/images/*`当中
