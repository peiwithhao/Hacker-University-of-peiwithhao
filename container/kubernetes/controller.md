# 控制器详解

# 实验一
步骤如下:
1. 使用minikube创建集群
```sh
minikube start      #开启集群，默认只有一个控制节点
minikube node add   #创建工作节点
```
实验中使用两个工作节点，一个控制节点,可以使用`minikube status`来查看

```sh
❯ minikube status
minikube
type: Control Plane
host: Running
kubelet: Running
apiserver: Running
kubeconfig: Configured

minikube-m02
type: Worker
host: Running
kubelet: Running

minikube-m03
type: Worker
host: Running
kubelet: Running
```

2. 使用`kubectl proxy --port 8080`命令来创建api server的代理服务器，让主机上面能够方便的访问到apiserver
接下来就可以使用浏览器或者curl来向apiserver发送请求






[https://www.zhaohuabing.com/post/2023-03-09-how-to-create-a-k8s-controller/](https://www.zhaohuabing.com/post/2023-03-09-how-to-create-a-k8s-controller/)
