# Audit system
audit是记录linux审计信息的内核模块。
他记录系统中的各种动作和事件，比如系统调用，文件修改，执行的程序，系统登入登出和记录所有系统中所有的事件。audit还可以将审计记录写入日志文件。

# 配置文件
他以一种服务进程的形式存在
```
❯ sudo systemctl status auditd
○ auditd.service - Security Audit Logging Service
     Loaded: loaded (/usr/lib/systemd/system/auditd.service; disabled; preset: disabled)
     Active: inactive (dead)
       Docs: man:auditd(8)
             https://github.com/linux-audit/audit-documentation
```

其配置脚本位于
`/etc/audit/auditd.conf`

# 使用
这里可以使用auditd给出的`auditctl`接口来添加监控规则
例如：
```sh
sudo auditctl -a always,exit -S all -F pid=<pid>
```
其中参数解释如下：
+ a always,exit: 表示添加规则， always和exit表示系统调用返回的时候进行监控
+ S all : 表示监控所有系统调用
+ -F pid= : 表示指定过规则，仅监控特定pid

查看审计日志可以使用另一个接口`ausearch`

```sh
sudo ausearch -p <pid>
```
也可以直接查看日志文件


当审计结束后你可以使用下面命令来删除规则

```sh
sudo auditctl -d always,exit -S all -F pid=<pid>
```
在平时的使用过程中，可以打印一个概述报告
```sh
aureport
```
这个命令会显示开启audit之后他记录的信息汇总

# 日志类型

auditd 主要记录以下几种类型的日志：

+ 用户活动日志：记录用户登录、登出、执行命令等活动。
+ 文件访问日志：监控对特定文件或目录的读取、写入和执行操作。
+ 系统调用日志：记录特定系统调用的执行情况，例如 open、read、write 等。
+ 权限变更日志：记录对系统权限和配置的修改，如用户添加、删除或权限更改。
+ 安全事件日志：记录与安全相关的事件，如 SELinux 相关的操作和其他安全策略的执行。



# 参考
[audit使用](https://www.cnblogs.com/wangguishe/p/17285807.html#_label2)



