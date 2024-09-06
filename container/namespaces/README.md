# !.Mount namespaces
要素: 第一个月进入Linux kernel 的namespace,首次出现在Linux 2.4.19

最开始只有一个初始命名空间,当某用户/进程调用clone()系统调用或unshare()系统调用来将调用者迁移到新的命名空间的时候
在创建新的命名空间的时候,新的namespace将会继承调用clone()或unshare()的进程的namespace中的全部挂载点列表

进程的 mount namespace 中的挂载点信息可以在 `/proc/[pid]/mounts、/proc/[pid]/mountinfo 和 /proc/[pid]/mountstats` 这三个文件中找到。

## !.!.如何使用mount namespace实现文件隔离

首先在根文件夹创建demo文件夹
```shell
$ sudo mkdir /demo && sudo chmod 777 /demo && cd /demo 
$ mkdr -p iso1/subdir1 iso2/subdir2
$ mkisofs -o 1.iso ./iso1
$ mkisofs -o 2.iso ./iso2
$ ls
1.iso  2.iso  iso1  iso2
```
这里我们创建了两个iso镜像,然后这里再创建两个挂载点
```shell
$ sudo mkdir /mnt/iso1 /mnt/iso2
$ sudo mount 1.iso /mnt/iso1
```

然后另起一个shell 名为shell2执行下面的命令,这个命令可以让当前进程会在一个新的mount namespace中运行,
```shell
$ sudo unshare -m
```
然后我们在两个shell中分别执行`readlink /proc/$$/ns/mnt`
```
mnt:[4026532697]
mnt:[4026531841]
```
我们会发现两次出现mount namespace不同,但是我们通过`mount | grep -i iso1`会发现两者的挂载点信息是相同的
接下来我们在shell2中执行mount和umount操作
```shell
$ mount 2.iso /mnt/iso2
$ umount /mnt/iso1
```
然后我们来分别查看shell1和shell2中的挂载点信息`mount | grep iso`

shell1
```shell
/demo/1.iso on /mnt/iso1 type iso9660 (ro,relatime,nojoliet,check=s,map=n,blocksize=2048,iocharset=utf8)
```

shell2
```shell
root@peiwithhao-Standard-PC-Q35-ICH9-2009:/demo# mount | grep iso
/demo/2.iso on /mnt/iso2 type iso9660 (ro,relatime,nojoliet,check=s,map=n,blocksize=2048,iocharset=utroot@peiwithhao-Standard-PC-Q35-ICH9-2009:/demo# 
```

这里就可以看出来差异,我们会发现两者的挂载点造成了隔离

## !.@.shared subtree
