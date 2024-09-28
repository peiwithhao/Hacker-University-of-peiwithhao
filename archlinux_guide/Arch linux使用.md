# Arch linux使用

[toc]

# 0x00.挂载/卸载qcow2文件系统

```shell
#!/bin/bash
############ 挂载 ##############
modprobe nbd max_part=16    #手动加载nbd模块,设置参数max_part=16
qemu-nbd -c /dev/nbd0 /path/to/image.qcow2 #将我们需要查看的qcow2文件系统连接到nbd(network block device)模块
partprobe /dev/nbd0 		#进行分区发现
fdisk -l /dev/nbd0 			#通过fdisk可以查看该分区的信息
mount /dev/nbd0p2 mountpoint 	#进行挂载

############ 卸载 ##############
umount mountpoint 			#挂载点卸载
qemu-nbd -d /dev/nbd0 	 	#取消nbd的链接
```

# 0x01.较常用的qemu启动脚本(x86_64版本)

首先是创建文件系统,有两种方式

```bash
dd if=/dev/zero of=ubuntu.img bs=1M count=8192
```

和

```bash
qemu-img create -f qcow2 win7.img 10G
```

```
#!/bin/bash
qemu-system-x86_64 \
    -enable-kvm \
    -m 1024 -smp 4 \
    -boot order=cd \
    -hda ./your/boot/disk/path/anything.qcow2'or'.img \
    -net user -net nic,model=virtio \
    -vga std \
    -nic user,model=e1000,mac=52:54:98:76:54:32 \
    -cdrom ./your/iso/path/anything.iso
```

# 0x02.pacman包管理

包的删除

```
sudo pacman -R package-name
sudo pacman -Rs package_name 	//删除依赖关系
sudo pacman -Rn package_name  	//pacman删除某些程序会备份重要配置文件,在其中后面加上*.pacsave扩展名,-n可以避免备份
sudo pacman -Rns $(pacman -Qdtq) 	//删除孤立包
```

升级软件包

```
sudo pacman -Syu
```

查询包数据库

```
pacman -Ss string1 string2 	//在包数据库中查询软件包
pacman -Qs string1 string2 	//查询已安装的软件包
pacman -F string1 string2 	//按文件名查找软件库
pacman -Si package_name 	//显示软件包详细信息
pacman -Qi package_name 	//显示本地安装包详细信息
pacman -Qii package_name 	//将同时显示备份文件和修改状态
pacman -Ql package_name 	//获取已安装软件包所包含文件的列表
pacman -Fl pacakge_name 	//查看远程库软件包包含的文件
pacman -Qk pacakge_name 	//查看软件包安装的文件是否都存在
pacman -Qdt 				//罗列所有孤立包
pacman -Qo filename         //查看该文件属于哪个包
```

清理包缓存

```
sudo paccache -r
sudo pacman -Sc 		//删除目前没有安装的所有缓存的包
sudo pacman -Scc 		//删除缓存所有文件,避免使用,这样会导致无法降级
```

其他

```
sudo pacman -Sw package_name 	//下载包但不安装他
sudo pacman -U /path/to/package/package_name-version.pkg.tar.zst 	//从本地安装下载好的包
sudo pacman -U file:///path/to/package/package_name-version.pkg.tar.zst 	//将本地包保存至缓存
sudo pacman -U http://www.example.com/repo/example.pkg.tar.zs 	//安装远程包
```

如果说使用pacman的时候出现以下情景

```sh
error: failed to synchronize all databases (unable to lock database)
```

这里说明有一个pacman已经在使用,我们此时需要删除 `/var/lib/pacman/db.lck`即可再次使用


如果说在重新安装某个包的时候,出现了文件冲突,可以采用下面的命令来覆盖掉相同的文件,前提当然是你知道自己在做什么😄

```sh 
pacman -S package-name --overwrite /usr/bin/libsndio.so
```
如果太多冲突的文件,并且你自身确定他确实需要覆盖,那么我们就可以使用下面的命令来批量修改

```sh 
$_ pacman -S package-name --overwrite '*'

```



# 0x03.网络管理

```
nmcli connection show 	//列出网络连接配置
nmcli device wifi list 	//查看附近wi-fi网络
nmcli device  			//查看所有网络设备以及状态
nmcli device wifi connect SSID_或_BSSID password 密码 //连接到 Wi-Fi 网络
nmcli device disconnect ifname eth0 //断开网络接口上的连接
nmcli c 	//查看连接记录
nmcli c del UUID 	//删除uuid连接
ss -at 					//显示所有TCP连接以及相应服务名
ss -atn 				//显示所有TCP俩皆以及端口号
ss -au 					//显示所有UDP连接
lsof -i :端口号 			//显示使用端口的进程

```

# 0x04.日志管理

```
journalctl --grep=PATTERN 		//显示PATTERN模式的日志
journalctl -b 					//显示本次启动的信息
journalctl -b -1 				//显示上次启动的信息
journalctl -b -2 				//显示上上次启动的信息
journalctl -p err..alert 		//只显示err/crit/emerg
journalctl --since="20xx-xx-xx xx:xx:xx" 	//显示从具体时间开始的消息
journalctl --since "20 min ago"
journalctl -f 								//显示最新消息
journalctl _PID=1 							//显示特定进程的所有消息
journalctl -k 								//显示内核缓存消息
journalctl --vacuum-size=100M 				//清理日志使总大小小于100M
journalctl --vacuum-time=2weeks 			//清理最早两周前的日志
journalctl --unit=UNIT 						//显示特殊systemd节点的日志信息,虽然这个似乎也可以通过systemctl status看
journalctl --user-unit=UNIT 				//同上,用户版
```

![image-20231205183801431](/home/peiwithhao/.config/Typora/typora-user-images/image-20231205183801431.png)

# 0x05.文件系统相关

## rsync

ssh连接中从远程文件与本地之间的同步，这里靠前的是源文件，靠后的是目的目录

```sh
rsync -avze "ssh -i /path/to/private_key" user@ip_address:/path/to/reomte_directory /path/to/local_directory 	//远程连接ssh若需要公钥时的拷贝
```

其中:

+ `-a`:以归档模式进行拷贝,保留文件的权限,时间戳等属性
+ `-v`:显示详细的输出信息,方便查看拷贝进度和日志
+ `-z`:启用压缩传输,减少数据传输量

```
rsync -P source destination     //其中-P与--partial --progress 选项的作用相同,显示进度, 可能需要使用-r/--recursive来递归到目录中传输
rsync source host:destination    //远程复制
rsync host:destination destination   //远程复制
```



## unzip

如果说unzip解压出现乱码,可能是默认编码的问题,如果说在windows上压缩的文件在linux上打开,我们可以使用下面的命令

```sh
unzip -O CP936 <filename.zip>
```

## ranger使用

### 1.排序

```
os: 按大小排序 
ob: 按名称排序 
ot: 按文件类型排序 
om:? 按 mtme(上一次修改文件内容的时间) 排序 
```

ranger 默认是以升序排列文件，你可以键入 “or” 使 ranger 以降序排列文件：

```
or: 反向排序 
```

### 2.书签

你可以设置一个书签以便快速的进入某个目录。

```
m<key>: 保存书签 
`<key>: 跳到书签 
um<key>: 删除书签
```

<key> 可以是任意的数字或字母。而且也 vim 不同，这写书签是永久保存的。

**
注：
1,  （键盘 `1` 左边的键） 和 `'`（单引号） 是等效的。
2, “`” 本身也是一个书签，代表上一次跳转的位置。你可以键入 ““” 跳到上一个跳转的位置。
**

### 3.标签页（tab）

ranger 支持多个标签页，可以快速地在多个标签页之间切换。

```
gn, Ctrl + N: 新建一个标签页 gt: 跳到下一个标签页 gT: 跳到上一个标签页 g<N>: 打开一个标签页，<N> 代表1到9的一个数字。如果这个标签页不存在的话，ranger 会自动创建。 gc, Ctrl + W: 关闭当前标签页，最后一个标签页不能关闭。 
```

### 4.选择文件

ranger 可以方便快速地选择多个文件。

使用V来开启/关闭选择模式

uv来撤销选择

space来撤销单个选择

```
t: 标记/取消标记选择的条目 T: 取消标记选择的条目 
```

### 5.查看文件

```
i: 查看当前文件的内容（文本文件） 
```

### 6.编辑文件

```
E: 调用默认编辑器编辑文件 
```

### 7.处理文件

```
:rename: 重命名 cw: 同 “:rename” A: 重命名，附加当前文件名 I: 同 “A”，但会将光标置于文件名之前 
yy: 复制 dd: 剪切 pp: 粘贴，当存在同名文件时，会自动重命名。 po: 粘贴，覆盖同名文件 pl: 创建一个被复制/剪切文件的符号链接。 pL: 创建一个被复制/剪切文件的符号链接（相对路径）。 
:delete 删除选定的条目 
```

如果删除的文件不止一个，ranger 会提示确认删除，键入 “y” 即可。也可以在输入命令时附加一个参数 “y”，跳过 ranger 的确认。

```
:delete y 
```

### 8.运行文件

```
l: 打开选定文件，同 
```

如果没有选定文件的话，则打开当前文件。

ranger 根据 apps.py 里面的定义来判断用什么程序来打开相应的文件。如果用户目录里没有文件 apps.py 的话，可以从 ranger/defaults/apps.py 复制到 ~/.config/ranger/ 下面。

如果 ranger 不知道用什么程序打开相应文件，会出现 “:open_with” 对话框询问用户。
也可以直接使用命令 ”r“ 打开 ”:open_with“ 对话框。

```
r: 用指定程序打开文件，同命令 ”:open_with“ 
```

:open_with 语法：

```
:open_with <program> <mode> <flags> 
```

<program>: 需要在 apps.py 中定义，CustomApplications 中每一个以 “app_” 开头的函数会被命令 “:open_with” 用到。

<mode>: ranger 以何种模式运行程序。可用的 mode 有：

```
0: 窗口模式 1: 全屏模式 
```

<flags>: 指定 ranger 以何种方式调用程序。

```
s: silence 模式。任何输出将被丢弃。 d: 分离程序（在后台运行）。 p: 将输入重定向到 pager 。 w: 当程序执行完成时需要用户回车确认。 
```

大写 flag 可以得到相反的作用，例如一个程序如果默认就在后台运行，那么可以使用 “:open_with D” 来防止其在后台运行。

按键 “S” 在当前目录下开启一个 shell ：

```
S: 在当前目录下开启一个 shell 。 
```

在执行某些操作（比如复制一个大文件）时不能立即完成，这在 ranger 中就是一个任务。你可以停止、启动某个任务，也可以对某个任务设置优先级。

```
w: 打开/关闭任务视图 dd: 终止一个任务 J: 降低当前任务的优先级 K: 提升当前任务的优先级 
```

命令以 “:” 开头。输入时可用 <Tab> 键补全，如果有多个匹配的，ranger 会依次遍历所有匹配项。

所有命令被定义在文件 ranger/defaults/commands.py 中。

可用的命令：

```
:cd <dirname> 跳转到目录 <dirname>  
:chmod <octal_number> 设置被选条目的权限  
:delete 删除被选条目  
:edit <filename> 编辑文件  
:filter <string> 只显示文件名中含有给定字符串 <string> 的文件  :find <regexp> 查找匹配给定正则表达式的文件，并且执行第一个匹配的文件  
:grep <string> 在选定的条目中查找给定的字符串 <string>  :mark <regexp> 选定匹配正则表达式的所有文件  
:unmark <regexp> 取消选定匹配正则表达式的所有文件  
:mkdir <dirname> 创建目录  
:open_with <program< <mode> <flags> 用给定的 <program>、<mode> 和 <flags> 打开文件。 所有参数都是可选的，未给出任何参数的时候，等价于 <Enter> 。  
:quit 退出 quit  
:rename <newname> 重命名当前文件  
:search <regexp> 搜索所有匹配正则表达式 <regexp> 的文件，相当与 vim 中的 “/”。快捷键： "/"  
:shell [-<flags>] <command> 运行命令 <command> 
:touch <filename> 创建文件 
```

所有的命令（”:delete” 除外），可以不用写全，不过前提是和之匹配的命令只有一个。

```
z: 切换设置 u: 撤销操作 W: 打开 message log du: 显示当前目录的磁盘占用情况 R: 刷新当前目录 Ctrl + R: 清空缓存并刷新目录。 Ctrl + L: 重画当前窗口。 
```

## ls

可以通过-i来显示文件的inode号

```
ls -i
```

## find

```
find <dir_path> -inum <inode_num>  //寻找inode号的文件
find <dir_path> -printf '<format>' 		//设置输出格式
```

## awk

输出指定列

```
awk '{print $1}' 		//打印输入信息的第一列
```



# 0x06.GDB调试

在我们兴奋的调试内核的过程当中，即使我们已经得到了充满信息符号的内核镜像，damn我们仍有许多内核函数并没有编译出来符号信息，此时我们可以通过文件和行号来进行断点

```
break filename:line_number
```





# 0x07.权限相关

查看当前进程所带权限

```
capsh --print
```

如果说没有capsh,那么我们也可以直接用原生态的linux proc虚拟文件系统来查看进程权限

```
cat /proc/self/status
```



# 0x08.窗口管理

```sh
xlsclients
```

显示wayland支持的程序

# 0x09.Hyprland 

## hyprpicker 取色器

`-f | --format=[fmt]` specifies the output format (`cmyk`, `hex`, `rgb`, `hsl`, `hsv`)

`-n | --no-fancy` disables the "fancy" (aka. colored) outputting

`-h | --help` prints a help message

`-a | --autocopy` automatically copies the output to the clipboard (requires [wl-clipboard](https://github.com/bugaevc/wl-clipboard))

`-r | --render-inactive` render (freeze) inactive displays too

`-z | --no-zoom` disable the zoom le

# 0x0A.阅读

博客批量修改

```
%s/!\[\(.*\)](\(.*\))/{% asset_image \2 %}
```



![](/home/peiwithhao/Pictures/screen_print/2024-07-21-10-21-26.png)

# 0x0B.编译

## make

如果make编译内核出现realloc报错,可以在`tools/lib/subcmd/Makefile`中的CFLAGS一项添加标志`-Wno-use-after-free` 

## GCC
无敌的编译器，编译选项如下：

- `-nostdlib`:命令链接器忽略标注你的libc链接惯例，只编译给出的代码
- `-c`:生成目标文件obj
- `-o`:生成可执行文件
- `-S`:生成汇编代码
- `gcc --verbose test.c ./glibc-2.31.so -o test`：glibc2.34以上若想编译低版本，可采用此法
- `-ftest-coverage`: 编译程序可以生成覆盖率文件,然后运行文件后可以看到执行了哪些文件

如果想静态链接静态库的话,如下使用

```
gcc test.c -o test -L/path/to/library -l:mylib.a
```

## strip
用来去除符号表，用法如下：
- `strip <elf>`：去除符号表

## pkg-config

主要是用来应用第三方库的时候来指明头文件和库文件,例如libfuse3的话,如下使用

```shell
pkg-config fuse3 --cflags --libs
```

这样返回的值在我的主机上面如下

```
-I/usr/include/fuse3 -lfuse3 -lpthread
```



# 0x0C.trace技巧

## ftrace
我们需要在内核中自行挂载该临时文件系统,挂载方式如下:
```
mount -t tracefs nodev /sys/kernel/tracing  //挂载tracefs
mount -t debugfs debugfs /sys/kernel/debug  //挂载debugfs
```
在我看来似乎两者差距不大,但是gpt给出的回答是tracefs更加适合性能调优,debugfs的使用场景则是深入了解操作系统内部状态

在挂载成功后我们可以来使用其提供的文件接口
这个文件用来查看当前的追踪者类型
```
/ # cat /sys/kernel/debug/tracing/current_tracer 
nop
```
其中类型我们可以通过`available_tracers`文件来查看
```
/sys/kernel/debug/tracing # cat available_tracers 
blk function_graph function nop
```
我们也可以查看trace是否开启
```
/sys/kernel/debug/tracing # cat tracing_on
1
```
下面正式使用ftrace


1. 设置tracer类型,这里设置为function
```
echo function > current_tracer
```
2. 设置过滤函数(tracer类型为function的情况下,这里的可选函数也可通过`available_filter_functions`)
```
echo dev_attr_show > set_ftrace_filter
```
除了追踪某些特定函数,也可以输出事件,我们可以通过命令`ls events`来查看

而chompie师傅是采用了trace event来进行追踪
我们可以方便的在内核启动参数添加trace_event=kmem:kmalloc,kmem:kfree来进行查看,此外我们也可以添加`no_hash_pointers`内核参数来删除虚拟内存地址的打印

3. 查看追踪信息,这里我们的trace记录要清空也很简单,`echo 0 > trace`
```
cat trace
```
此外其也可以对于二进制文件本身的函数调用追踪，为Ryan O'Neill所著作，地址如下：

[https://github.com/elfmaster/ftrace](https://github.com/elfmaster/ftrace)

- `ftrace [-p <pid>] [-Sstve] <prog> <args>`:用法如下：
- `[-p]`:根据PID追踪
- `[-t]`:检测函数参数的类型
- `[-s]`:打印字符串值
- `[-v]`:显示详细输出
- `[-e]`:显示各种ELF信息（符号、依赖）
- `[-S]`:显示确实了符号的函数调用
- `[-C]`:完成控制流分析


## strace
system call trace,基于ptrace(2)系统调用，可以用来收集运行时系统调用相关信息

- `strace /bin/ls -o ls.out`:使用strace来跟踪一个基本程序
- `strace -p <pid> -o daemon.out`:使用strace命令附加到一个现存的进程上，原始输出将会现实每个系统调用的文件描述编号，系统调用会将文件描述符作为参数，例如：`SYS_READ(3, buf, sizeof(buf))`
- `strace -e read=3 /bin/ls`:查看读入到文件描述符3中的所有数据，也可以使用`-e write=3`查看写入的情况

## ltrace
library trace,他会解析共享库，也就是一个程序的链接信息，并打印处用到的库函数

- `ltrace <program> -o program.out`:通过解析可执行文件的动态段并打印出共享库和静态库的实际符号和函数

# 0x0D.二进制分析

## patchelf
用来修改ELF文件中动态库和链接器的绑定关系

- `patchelf --set-rpath <libc.so.6_directory> <elf>`:修改动态库绑定关系
- `patchelf --set-interpreter <ld> <elf>`:修改动态链接器绑定关系


## objdump
用来分析目标文件或可执行

- `objdump -D <elf_object>`:查看ELF文件所有节的数据或代码
- `objdump -d <elf_object>`:查看ELF文件中的程序代码
- `objdump -tT <elf_object>`:查看所有符号

## objcopy
分析和修改任意类型的ELF目标文件，可以修改ELF节，或进行复制

- `objcopy -only-section=.data <infile> <outfile>`:将data节从一个ELF文件复制到另一个文件中

## readelf
解析ELF二进制文件

- `readelf -S <object>`:查询节头表
- `readelf -l <object>`:查询程序头表
- `readelf -s <object>`:查询程符号表
- `readelf -h <object>`:查询ELF文件头数据
- `readelf -r <object>`:查询重定位入口
- `readelf -d <object>`:查询动态段

# 0x0E.特殊文件

## /proc/<pid\>/maps
保存了一个进程镜像的布局，包括可执行文件、共享库、栈、堆和VDSO

## /proc/kcore
Linux内核的动态核心文件，他是以ELF核心文件的形式所展现出来的原生内存转储，GDB可以使用他来对内核进行调试和分析

## /boot/System.map
包含整个内核的所有符号

## /proc/kallsyms
与上面类似，区别就是kallsyms是内核所属的/proc的一个入口并且可以动态更新。如果说安装了新的LKM，符号会自动添加到/proc/kallsyms当中。他包含大部分符号，如果在`CONFIG_KALLSYMS_ALL`内核配置中指明，则可以包含内核中全部的符号。

## /proc/iomem
与`/proc/<pid>/maps`类似，如果想知道内核的text段所映射的物理内存位置，可以搜索Kernel字符串，利用如下指令：

	dawn@dawn-virtual-machine:~$ sudo grep Kernel /proc/iomem
	[sudo] password for dawn: 
	  21000000-220025c7 : Kernel code
	  22200000-22c8dfff : Kernel rodata
	  22e00000-232466ff : Kernel data
	  23598000-23bfffff : Kernel bss

## /proc/cmdline

显示内核启动参数



# 0x0F.服务管理

通常如果要删除服务,那么可以使用systemctl首先暂停服务

如果是用户服务,那么需要找到他的*.service文件然后删除

最后使用`systemctl daemon-reload`来重新加载systemd


# 0x10.Python相关
如果希望接下来的实验位于一个python测试环境,那么可以利用python自带的venv,使用方法如下:
```sh
$ python -m venv <your tmp directory path>
$ cd <your tmp directory path>
$ source bin/activate
```
执行上述步骤我们以后使用python就是为刚刚的创建环境的python版本,并且在本shell下所构建的python包也会位于你所创建临时目录下
如果希望卸载,我们可以在当前shell直接使用下面命令
```sh
$ deactivate
```

# 0x11.屏幕录制/截取
推荐使用wf-recorder
```shell
$ wf-recorder --audio -o file_name -g "$(slurp)"
```
而这里的audio有时会默认为输入的麦克风,我们可以在此指定相关内容
而音频设备可以用以下指令查看
```sh
❯ pactl list sources | grep "名称"
	名称：alsa_output.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__HDMI3__sink.monitor
	名称：alsa_output.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__HDMI2__sink.monitor
	名称：alsa_output.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__HDMI1__sink.monitor
	名称：alsa_output.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__Speaker__sink.monitor
	名称：alsa_input.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__Mic2__source
	名称：alsa_input.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__Mic1__source
	名称：bluez_sink.CC_14_BC_B5_89_61.a2dp_sink.monitor
```








