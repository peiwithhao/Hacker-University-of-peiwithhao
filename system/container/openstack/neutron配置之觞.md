# 配置neutron
出现的问题如下
1. openstack能正常dhcp分配IP,
但VM内部 `ip a` 所获得的IP并不一致，且无法ping通网关
2. 修改VM内部的IP之后发现能正常与外界通信

# dnsmasq
neutron的DHCP分配服务是由dnsmasq来决定的,所以可以查看dnsmasq进程
```sh
ps aux | grep dnsmasq
```
通过其获得的输出可以知道现在的静态IP分配池,但发现其仍然是openstack提供的IP 


# VM
VM所在的计算节点上查看他的配置文件
```xml
...
<interface type='ethernet'>
      <mac address='fa:16:3e:e9:74:75'/>
      <target dev='tap7747ce3b-41'/>
      <model type='virtio'/>
      <mtu size='1500'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
...
```

在控制节点上面抓对应的`br-provider`的包发现VM的dhcp命令确实走到这里，但是其请求的`192.168.122.1`
因此我决定将网关地址换成控制节点(因为这上面运行着dnsmasq,也就是dhcp的服务器)
并且将宿主机的libvirt的dhcp选项也给关闭，因为这个集群基本也都是静态IP
,但是切换之后发现VM直接无法显示网关了:(




# 参考
[https://blog.csdn.net/nb_zsy/article/details/106816607](https://blog.csdn.net/nb_zsy/article/details/106816607) 
