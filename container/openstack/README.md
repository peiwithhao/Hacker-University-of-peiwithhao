<!--toc:start-->
- [OpenStack IaaS部署文档](#openstack-iaas部署文档)
  - [配置环境](#配置环境)
    - [配置静态IP](#配置静态ip)
    - [配置域名解析](#配置域名解析)
    - [关闭防火墙和Selinux/AppArmor](#关闭防火墙和selinuxapparmor)
    - [同步时间](#同步时间)
  - [服务配置](#服务配置)
    - [MySQL](#mysql)
- [参考](#参考)
<!--toc:end-->

# OpenStack IaaS部署文档
+ 宿主机环境: Ubuntu 24.04 LTS
+ 内核版本: 6.8.0
+ openstack: 

## 配置环境
初始仅考虑三节点环境

+ node1:
    role: controller
    发行版: Ubuntu 24.04LTS
    内核: 6.8.0

+ node2:
    role: compute
    发行版: Ubuntu 24.04LTS
    内核: 6.8.0

+ node3:
    role: compute
    发行版: Ubuntu 24.04LTS
    内核: 6.8.0

### 配置静态IP
由于libvirt默认是采用NAT网络，所以这里可以通过`ip a show <网卡>`,来查看子网网段
这也是虚拟机的默认路由，因此我们可以分别在三个节点中配置适当的静态IP

```sh
29: virbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 52:54:00:3b:73:6b brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0
       valid_lft forever preferred_lft forever
```

分别将三个node的静态IP配置为
+ 192.168.122.10(controller)
+ 192.168.122.11(compute1)
+ 192.168.122.12(compute2)


> [!note]
> ubuntu的静态IP配置方法是修改`/etc/netplan/*.yaml`文件,修改完毕后使用`sudo netplan apply`


### 配置域名解析
分别配置控制节点和计算节点

```sh
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
192.168.122.10       openstack-cotroller.iie.com
192.168.122.11       openstack-controller.iie.com
```

### 关闭防火墙和Selinux/AppArmor

控制节点和计算节点均需要配置

Ubuntu server默认并不开启Selinux,因此这里仅仅关闭apparmor和防火墙
可以使用`sudo aa.status`来查看apparmor的开启状态


```sh
sudo systemctl stop apparmor # 停止服务
sudo systemctl disable apparmor && sudo systemctl mask apparmor # 禁止服务自启动
```

然后用类似的方式关闭防火墙
```sh

sudo systemctl stop ufw # 停止服务
sudo systemctl disable ufw # 禁止服务自启动
```



### 同步时间
主要是安装chrony进行同步

在控制节点
```sh
sudo apt install chrony
echo "allow 192.168.122.0/24" >> /etc/chrony/chrony.conf  # 允许该网段下的主机
echo "local stratum 10" >> /etc/chrony/chrony.conf   # 将自身标记为ntp服务器
sudo systemctl restart chrony && sudo systemctl enable chrony
```


在计算节点
```sh
sudo apt instal chrony
echo "source 192.168.122.10" >> /etc/chrony/chrony.conf
sudo systemctl restart chrony && sudo systemctl enable chrony
sudo chronyc sources     # 查看支持的ntp服务器
```

在布置好后可以在控制节点查看同步时间的机器`chronyc clients`


## 服务配置

### MySQL/MariaDB
下面的服务默认均在控制节点配置

```sh
sudo apt install mariadb-server
openssl rand -hex 10 # 生成密码,这个密码在配置openstack会需要
vim /etc/mysql/mariadb.conf.d/50-server.cnf
cat /etc/mysql/mariadb.conf.d/50-server.cnf
sudo mysql_secure_installation  # 过程中会要求输入密码
```

### 消息队列RabbitMQ
他是一个消息队列管理框架,ubuntu 24.04通过下面的方式安装
`sudo apt install rabbitmq-server`
`systemctl enable rabbitmq-server && systemctl start rabbitmq-server`

添加rabbitmq 用户
```sh
rabbitmqctl add_user "openstack" <passwd>  # 创建用户
sudo rabbitmqctl set_permissions openstack ".*" ".*" ".*"  #设置权限
sudo rabbitmqctl set_user_tags openstack administrator # 将用户设置为管理员
```


启动web页面插件
```sh
rabbitmq-plugins enable rabbitmq_management
systemctl restart rabbitmq-server # 重启服务
```

然后就可以访问页面`192.168.122.10:15672`登陆rabbitmq, 默认管理员账号为guest/guest


### KeyStone 配置
使用mariadb来创建KeyStone数据库
```sh
mysql -u root -p 
MariaDB [(none)]> CREATE DATABASE keystone;   # 创建数据库
MariaDB [(none)]> GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY '9b7976d96ef6ecadccce'; # 创建本地访问用户
MariaDB [(none)]> GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%' IDENTIFIED BY '9b7976d96ef6ecadccce'; # 创建远程访问用户
```

安装keystone和memcached
memcached主要功能是加速访问数据，他将访问的数据缓存到内存当中来进行加速,而不用每次都从数据库或内存中取出
而在openstack中搭配keystone主要是用来缓存Token

而KeyStone是openstack的认证服务,主要负责用户认证,授权

```sh
sudo apt install keystone memcached python3-openstackclient
```

然后配置keystone
其配置文件与`/etc/keystone/keystone.conf`进行配置
```sh

[root@openstack ~]# vim /etc/keystone/keystone.conf
[DEFAULT]    #定义初始管理令牌的值
admin_token = 58d48e8481d5f01b6ca0

[database]    #配置数据库访问
connection = mysql+pymysql://keystone:9b7976d96ef6ecadccce@127.0.0.1/keystone

[revoke]    #配置回滚驱动
driver = sql

[token]    #配置Fernet UUID令牌的提供者
provider = fernet    
```



需要保证memcached服务自启动并开启

然后初始化keystone数据库
这条命令的意义就是用keystone用户来执行`keystone-manage db_sync`初始化和同步openstack数据库：
`su -s /bin/sh -c "keystone-manage db_sync" keystone`
这条命令用来初始化fernet令牌，该令牌用来生成token：
`keystone-manage fernet_setup --keystone-user keystone --keystone-group keystone`

### Apache HTTP配置
安装
```sh
sudo apt install apache2 libapache2-mod-wsgi-py3
sudo a2enmod wsgi    #启动必要模块，一般来说都已经启动
sudo a2enmod rewrite
```

创建keystone配置文件,位于
`/etc/apache2/sites-available/wsgi-keystone.conf`

填入:
```sh

Listen 5000
Listen 35357

<VirtualHost *:5000>
    WSGIDaemonProcess keystone-public processes=5 threads=1 user=keystone group=keystone display-name=%{GROUP}
    WSGIProcessGroup keystone-public
    WSGIScriptAlias / /usr/bin/keystone-wsgi-public
    WSGIApplicationGroup %{GLOBAL}
    WSGIPassAuthorization On
    ErrorLogFormat "%{cu}t %M"
    ErrorLog /var/log/apache2/keystone-error.log
    CustomLog /var/log/apache2/keystone-access.log combined

    <Directory /usr/bin>
        Require all granted
    </Directory>
</VirtualHost>

<VirtualHost *:35357>
    WSGIDaemonProcess keystone-admin processes=5 threads=1 user=keystone group=keystone display-name=%{GROUP}
    WSGIProcessGroup keystone-admin
    WSGIScriptAlias / /usr/bin/keystone-wsgi-admin
    WSGIApplicationGroup %{GLOBAL}
    WSGIPassAuthorization On
    ErrorLogFormat "%{cu}t %M"
    ErrorLog /var/log/apache2/keystone-error.log
    CustomLog /var/log/apache2/keystone-access.log combined

    <Directory /usr/bin>
        Require all granted
    </Directory>
</VirtualHost>
```

然后启用keystone站点
```sh
sudo a2ensite wsgi-keystone.conf
```
之后重新启动apache2


## Openstack配置
首先需要设置一些相关的环境变量


# 参考
[https://ubuntu.com/tutorials/install-openstack-on-your-workstation-and-launch-your-first-instance#2-install-openstack](https://ubuntu.com/tutorials/install-openstack-on-your-workstation-and-launch-your-first-instance#2-install-openstack)
[https://canonical.com/microstack/docs/single-node](https://canonical.com/microstack/docs/single-node)
[https://www.cnblogs.com/thesungod/p/17612213.html](https://www.cnblogs.com/thesungod/p/17612213.html)
[https://developer.huawei.com/consumer/cn/forum/topic/0202490209538630152](https://developer.huawei.com/consumer/cn/forum/topic/0202490209538630152)
[https://www.cnblogs.com/xiexun/p/17876082.html](https://www.cnblogs.com/xiexun/p/17876082.html)
[https://www.cnblogs.com/powell/p/17958801](https://www.cnblogs.com/powell/p/17958801)
