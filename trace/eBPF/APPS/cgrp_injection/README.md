# cgrp注入测试实况

# 环境参数

+ 操作系统: 
`Linux peiwithhao-Standard-PC-Q35-ICH9-2009 6.11.0-061100-generic #202409151536 SMP PREEMPT_DYNAMIC Sun Sep 15 16:01:12 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux`
+ 内存情况: 
```sh
               total        used        free      shared  buff/cache   available
Mem:            15Gi       1.8Gi        10Gi        37Mi       2.9Gi        13Gi
Swap:          2.0Gi          0B       2.0Gi
```
+ 硬盘情况: 
```sh
Filesystem      Size  Used Avail Use% Mounted on
tmpfs           1.6G  2.0M  1.6G   1% /run
/dev/vda3        98G   34G   59G  37% /
tmpfs           7.9G     0  7.9G   0% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
/dev/vda2       512M  6.1M  506M   2% /boot/efi
tmpfs           1.6G  100K  1.6G   1% /run/user/1000
```

+ cpu核心情况:
```sh
Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          39 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   6
```
+ 集群创建: `kind v0.30.0 go1.24.6 linux/amd64`
+ 运行时版本: 
```sh
Client:
 Version:           27.5.1
 API version:       1.47
 Go version:        go1.22.2
 Git commit:        27.5.1-0ubuntu3~22.04.2
 Built:             Mon Jun  2 12:18:38 2025
 OS/Arch:           linux/amd64
 Context:           default

Server:
 Engine:
  Version:          27.5.1
  API version:      1.47 (minimum version 1.24)
  Go version:       go1.22.2
  Git commit:       27.5.1-0ubuntu3~22.04.2
  Built:            Mon Jun  2 12:18:38 2025
  OS/Arch:          linux/amd64
  Experimental:     false
 containerd:
  Version:          1.7.27
  GitCommit:        
 runc:
  Version:          1.2.5-0ubuntu1~22.04.1
  GitCommit:        
 docker-init:
  Version:          0.19.0
  GitCommit:        
```

+ k8s集群版本:
```sh
Client Version: v1.34.1
Kustomize Version: v5.7.1
Server Version: v1.34.0
```


# 测试应用
```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  selector:
    app: nginx
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
    nodePort: 30080
  type: NodePort
```




