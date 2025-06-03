来自于ArchWiki的设置
# 网络
## 数据链路层
qemu默认给虚拟机的macaddr是`52:54:00:12:34:56`,
但是当多台虚拟机在搭建桥接设备的时候
每台虚拟机在tap虚拟机端口都需要有独一无二的mac地址
因此多台虚拟机运行时需要自己进行定义mac地址，每个mac地址是`52:53:XX:XX:XX:XX:XX:XX`，通过以下命令

```qemu
-netdev user,id=mynic0 -device e1000,netdev=mynic0,mac=52:54:98:76:54:32
```

netdev主要用来配置网络后端，device参数则是用来配置虚拟网卡
这里是配置的用户网络
## user网络
可以用来进行主机的端口转发
在netdev的选项中有下面这一项
```sh
hostfwd=[tcp|udp]:[hostaddr]:hostport-[guestaddr]:guestport
```

例子如下
```sh
-device e1000,netdev=mynic0 \
-netdev user,id=mynic0,host=10.0.2.10,hostfwd=tcp:127.0.0.1:29776-:22 \
```



## Tap网络

qemu默认启用的是用户网络，可以进行简单的访问网络操作，
但如果需要利用到虚拟机/宿主机间通信需要开启tap网络

Tap device是linux内核提供的模拟真实网络接口的工具，
而qemu可以利用tap网络来让经过该tap网络的数据传递给vm
默认例子可以如下配置

```sh
-device e1000,netdev=nd0 \
-netdev tap,id=nd0,ifname=tap0,script=no \
```

他会自动在宿主机创建一个名称为tap0虚拟网卡,这个网卡用来虚拟机间通信
