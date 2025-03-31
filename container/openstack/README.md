<!--toc:start-->
- [OpenStack IaaS部署文档](#openstack-iaas部署文档)
  - [配置环境](#配置环境)
    - [配置静态IP](#配置静态ip)
    - [配置域名解析](#配置域名解析)
    - [关闭防火墙和Selinux/AppArmor](#关闭防火墙和selinuxapparmor)
    - [同步时间](#同步时间)
  - [服务配置](#服务配置)
    - [MySQL/MariaDB](#mysqlmariadb)
    - [消息队列RabbitMQ](#消息队列rabbitmq)
    - [KeyStone 配置](#keystone-配置)
    - [Apache HTTP配置](#apache-http配置)
  - [Openstack配置](#openstack配置)
    - [创建认证服务的API端点](#创建认证服务的api端点)
    - [创建default域](#创建default域)
    - [创建admin项目](#创建admin项目)
    - [创建admin 用户并设置密码](#创建admin-用户并设置密码)
    - [创建admin 角色](#创建admin-角色)
    - [添加admin 角色到admin用户和admin项目上](#添加admin-角色到admin用户和admin项目上)
    - [创建Service项目和Demo项目](#创建service项目和demo项目)
    - [创建demo用户](#创建demo用户)
    - [创建user角色](#创建user角色)
    - [验证token](#验证token)
  - [Glance安装](#glance安装)
    - [openstack glance配置](#openstack-glance配置)
    - [安装glance](#安装glance)
  - [Placement安装](#placement安装)
    - [placement配置](#placement配置)
    - [安装placement](#安装placement)
  - [Neutron 安装](#neutron-安装)
  - [Nova 安装](#nova-安装)
    - [Nova 配置](#nova-配置)
    - [安装nova](#安装nova)
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

下面和条命令用来创建认证机制
```sh
keystone-manage credential_setup --keystone-user keystone --keystone-group keystone
```

然后是设置初始的一些内容
```sh
keystone-manage bootstrap --bootstrap-password ADMIN_PASS \
  --bootstrap-admin-url http://controller:5000/v3/ \
  --bootstrap-internal-url http://controller:5000/v3/ \
  --bootstrap-public-url http://controller:5000/v3/ \
  --bootstrap-region-id RegionOne
```


这里注意需要将url修改，在v3之后实际上就只需要5000端口，35357可以滚了(

> [!note]
> Before the Queens release, keystone needed to be run on two separate ports to accommodate 
> the Identity v2 API which ran a separate admin-only service commonly on port 35357. 
> With the removal of the v2 API, keystone can be run on the same port for all interfaces.




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

> [!note]
> 这里需要注意的是官网提出需要在`/etc/apache2/apache2.conf`里面配置`ServerName openstack-controller.iie.com`

## Openstack配置
首先需要设置一些相关的环境变量

```sh
export OS_USERNAME=admin
export OS_PASSWORD=ADMIN_PASS
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_AUTH_URL=http://controller:5000/v3
export OS_IDENTITY_API_VERSION=3
```
这里的`ADMIN_PASS`需要自行替换

然后调用openstack cli创建keystone服务(但在上面keystone-manage bootstrap流程的时候已经创建了keystone service和default domain)
```sh
openstack service create --name keystone --description "OpenStack Identity" identity
```

我们可以通过`openstack service list`来查看服务列表

### 创建认证服务的API端点
```sh
openstack endpoint create --region RegionOne identity public http://openstack-controller.iie.com:5000/v3
openstack endpoint create --region RegionOne identity internal http://openstack-controller.iie.com:5000/v3
openstack endpoint create --region RegionOne identity admin http://openstack-controller.iie.com:5000/v3
```

这样就创建了三个API端点
### 创建default域

同service已经存在，下面是创建的命令
```sh
openstack domain create --description "Default Domain" default
```

### 创建admin项目
同上已经存在
```sh
openstack project create --domain default --description "Admin Project" admin
```

### 创建admin 用户并设置密码

同上
```sh
openstack user create --domain default --password-prompt admin
```

### 创建admin 角色
```sh
openstack role create admin
```

### 添加admin 角色到admin用户和admin项目上
```sh
openstack role add --project admin --user admin admin
```

### 创建Service项目和Demo项目

```sh
openstack project create --domain default --description "Service Project" service
openstack project create --domain default --description "Demo Project" demo
```

### 创建demo用户
```sh
openstack user create --domain default --password-prompt demo
```

### 创建user角色
```sh
openstack role create user
```

并将其添加到demo项目和demo用户上

### 验证token
在OS_*等的配置下，我们可以使用`openstack token issue`来获取token详细信息
因此可以将其写为不同的脚本进行设置环境变量

## Glance安装
Glance 是一个镜像服务，主要用于管理虚拟机镜像
这里的配置首先是添加对应数据库，这里的密码同样也是使用openssl生成
方法和将keystone添加到数据库一致，这里就不赘述

### openstack glance配置
admin用户使用openstack来创建glance用户
```sh
openstack user create --domain default --password-prompt glance
openstack role add --project service --user glance admin   # 将admin角色添加到glance用户和service项目
openstack service create --name glance --description "OpenStack Image" image # 添加glance服务

openstack endpoint create --region RegionOne image public http://openstack-controller.iie.com:9292
openstack endpoint create --region RegionOne image admin http://openstack-controller.iie.com:9292
openstack endpoint create --region RegionOne image internal http://openstack-controller.iie.com:9292
```

### 安装glance
```sh
sudo apt install glance python3-glanceclient
```

然后配置`/etc/glance/glance-api.conf`

具体配置可以查看[官网](https://docs.openstack.org/glance/xena/install/install-ubuntu.html)
初始化glance数据库,设置glance服务自启动

```sh
su -s /bin/sh -c "glance-manage db_sync" glance
systemctl enable glance-api
systemctl restart glance-api

source admin-openrc
openstack image list
```

然后就可以添加镜像文件
```sh
wget http://download.cirros-cloud.net/0.3.4/cirros-0.3.4-x86_64-disk.img
openstack image create "cirros" --file cirros-0.3.4-x86_64-disk.img --disk-format qcow2 --container-format bare --public
openstack image list
```


## Placement安装
主要负责资源的统计

```mysql
MariaDB [(none)]> CREATE DATABASE placement;
MariaDB [(none)]> GRANT ALL PRIVILEGES ON placement.* TO 'placement'@'localhost' \
  IDENTIFIED BY 'PLACEMENT_DBPASS';
MariaDB [(none)]> GRANT ALL PRIVILEGES ON placement.* TO 'placement'@'%' \
  IDENTIFIED BY 'PLACEMENT_DBPASS';
```

### placement配置
1. 创建用户，服务，并配置role
```sh
openstack user create --domain default --password-prompt placement
openstack role add --project service --user placement admin
openstack service create --name placement \
  --description "Placement API" placement
```

2. 配置endpoint
```sh
openstack endpoint create --region RegionOne  placement admin http://openstack-controller.iie.com:8778
openstack endpoint create --region RegionOne  placement public http://openstack-controller.iie.com:8778
openstack endpoint create --region RegionOne  placement internal http://openstack-controller.iie.com:8778
```

### 安装placement
```sh
apt install placement-api
```

接下来需要配置`/etc/placement/placement.conf`
需要修改的部分同样可以查看[官方文档](https://docs.openstack.org/placement/latest/install/install-ubuntu.html#configure-user-and-endpoints)

全部配完之后更新一下数据库即可
```sh
su -s /bin/sh -c "placement-manage db sync" placement
```




## Nova 安装
Nova主要负责在IaaS集群当中的虚拟机创建管理删除调度功能等等

### Nova 配置

首先第一步也是创建数据库

```mysql
MariaDB [(none)]> CREATE DATABASE nova_api;
MariaDB [(none)]> CREATE DATABASE nova;
MariaDB [(none)]> CREATE DATABASE nova_cell0;
MariaDB [(none)]> GRANT ALL PRIVILEGES ON nova_api.* TO 'nova'@'localhost' \
  IDENTIFIED BY 'NOVA_DBPASS';
MariaDB [(none)]> GRANT ALL PRIVILEGES ON nova_api.* TO 'nova'@'%' \
  IDENTIFIED BY 'NOVA_DBPASS';

MariaDB [(none)]> GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'localhost' \
  IDENTIFIED BY 'NOVA_DBPASS';
MariaDB [(none)]> GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'%' \
  IDENTIFIED BY 'NOVA_DBPASS';

MariaDB [(none)]> GRANT ALL PRIVILEGES ON nova_cell0.* TO 'nova'@'localhost' \
  IDENTIFIED BY 'NOVA_DBPASS';
MariaDB [(none)]> GRANT ALL PRIVILEGES ON nova_cell0.* TO 'nova'@'%' \
  IDENTIFIED BY 'NOVA_DBPASS';
```

第二部分，创建openstack nova用户,并给予权限
```sh
openstack user create --domain default --password-prompt nova
openstack role add --project service --user nova admin
openstack service create --name nova --description "OpenStack Compute" compute
```

第三部分，创建endpoint
```sh
 openstack endpoint create --region RegionOne compute public http://openstack.if010.com:8774/v2.1/%\(tenant_id\)s
 openstack endpoint create --region RegionOne compute internal http://openstack.if010.com:8774/v2.1/%\(tenant_id\)s
 openstack endpoint create --region RegionOne compute admin http://openstack.if010.com:8774/v2.1/%\(tenant_id\)s
```


### 安装nova
```sh
apt install nova-api nova-conductor nova-novncproxy nova-scheduler
```

配置文件，参考[官网](https://docs.openstack.org/nova/latest//install/controller-install-ubuntu.html)

配置完毕后本地出了一个py库的错误，但是官网说可以忽略所有问题

1. 激活nova-api数据库
```sh
su -s /bin/sh -c "nova-manage api_db sync" nova
```
2. 注册cell0数据库
```sh
su -s /bin/sh -c "nova-manage cell_v2 map_cell0" nova
```
3. 创建cell1
```sh
su -s /bin/sh -c "nova-manage cell_v2 create_cell --name=cell1 --verbose" nova
```
4. 激活nova数据库
```sh
su -s /bin/sh -c "nova-manage db sync" nova
```
5. 确认cell0和cell1被注册
```sh
su -s /bin/sh -c "nova-manage cell_v2 list_cells" nova
```



### 计算节点的配置
首先安装相关包
```sh
apt install nova-compute
```

## Neutron 安装

### Neutron配置
在 OpenStack 中，Neutron 是网络服务组件，负责为 OpenStack 环境中的虚拟机（VM）、容器或裸机提供 网络连接与管理功能。
他的配置过程同上面类似，都是首先创建数据库和openstack的配置
```sh
openstack user create --domain default --password-prompt neutron
openstack role add --project service --user neutron admin
openstack service create --name neutron \
  --description "OpenStack Networking" network
openstack endpoint create --region RegionOne \
  network public http://controller:9696
```

### 按装Neutron
```sh
apt install neutron-server neutron-plugin-ml2 \
  neutron-openvswitch-agent neutron-dhcp-agent \
  neutron-metadata-agent
```

配置文件可以参考[https://www.cnblogs.com/thesungod/p/17612213.html](https://www.cnblogs.com/thesungod/p/17612213.html)


正式安装
```sh
su -s /bin/sh -c "neutron-db-manage --config-file /etc/neutron/neutron.conf \
  --config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade head" neutron
```
万事后重启nova和一些neutron的服务

```sh
service neutron-server restart
service neutron-openvswitch-agent restart
service neutron-dhcp-agent restart
service neutron-metadata-agent restart
```

### 计算节点的配置
首先安装相关包
```sh
sudo apt install -y neutron-linuxbridge-agent ebtables ipset
```


# 参考
[https://ubuntu.com/tutorials/install-openstack-on-your-workstation-and-launch-your-first-instance#2-install-openstack](https://ubuntu.com/tutorials/install-openstack-on-your-workstation-and-launch-your-first-instance#2-install-openstack)
[https://canonical.com/microstack/docs/single-node](https://canonical.com/microstack/docs/single-node)
[https://www.cnblogs.com/thesungod/p/17612213.html](https://www.cnblogs.com/thesungod/p/17612213.html)
[https://developer.huawei.com/consumer/cn/forum/topic/0202490209538630152](https://developer.huawei.com/consumer/cn/forum/topic/0202490209538630152)
[https://www.cnblogs.com/xiexun/p/17876082.html](https://www.cnblogs.com/xiexun/p/17876082.html)
[https://www.cnblogs.com/powell/p/17958801](https://www.cnblogs.com/powell/p/17958801)
