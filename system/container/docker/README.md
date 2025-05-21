# !. 构建Dockerfile

<!--toc:start-->
- [!. 构建Dockerfile](#构建dockerfile)
  - [!.!. FROM](#from)
  - [!.@. RUN](#run)
  - [!.#. COPY](#copy)
  - [!.$. ADD](#add)
  - [!.%. CMD](#cmd)
  - [!.^. ENTRYPOINT](#entrypoint)
  - [!.&. ENV](#env)
  - [!.*. ARG](#arg)
<!--toc:end-->

首先说一下其中Dockerfile的格式

## !.!. FROM
指定基础镜像,比如我可以指定ubuntu 18.04作为基础镜像
```Dockerfile
FROM ubuntu:20.04
```

## !.@. RUN
指令用于在镜像中执行命令.可以使用镜像的指令安装软件包/执行编译操作等
```Dockerfile
RUN apt-get update && apt-get install -y curl
```

## !.#. COPY
COPY用于将文件或目录从构建环境复制到镜像中
```Dockerfile
COPY app.py /app/
```
## !.$. ADD
类似于COPY,但其支持自动解压缩包,建议尽量使用COPY
```Dockerfile
ADD archive.tar.gz /data/
```

## !.%. CMD
CMD指令用于指定容器启动的默认执行的命令,一个Dockerfile只能存在一个CMD指令
```Dockerfile
CMD ["python", "app.py"]
```
这里做出差异就是CMD在docker run时运行,RUN是在docker build期间运行

## !.^. ENTRYPOINT
类似于CMD,但不会被docker run命令行中的参数覆盖
```Dockerfile
ENTRYPOINT ["python"] CMD ["app.py"]
```
将python设置为容器的默认执行命令,并且可以通过docker run 的参数指定要执行的app.py

如果Dockerfile中存在多个ENTRYPOINT指令,仅最后一个生效

这在开启docker的时候传递参数,则会默认使用ENTRYPOINT的默认执行命令

## !.&. ENV
该指令用于设置环境变量,可以在Dockerfile中使用环境变量,并且它们会传递到容器运行时环境
```Dockerfile
ENV APP_HOME /app WORKDIR $APP_HOME
```
ENV命令设置APP_HOME的环境变量为/app, 然后把工作目录切换到$APP_HOME里面

## !.*. ARG
该指令用于定义构建参数,可以在构建镜像时传递
```python
ARG VERSION RUN echo $VERSION
```
该指令定义来一个名为VERSION的构建参数,并在构建的时候输出值

## !.(. EXPOSE
用于声明容器运行时监听的端口,例如
```Dockerfile
EXPOSE 8080
```

## !.!). WORKDIR
设置工作目录, 该目录将用作后续指令的默认路径
```Dockerfile
WORKDIR /app
```

## !.!!. VOLUME
用于在镜像中创建一个或多个挂载点,容器可以将这些挂载点暴露给主机或其他容器
```Dockerfile
VOLUME /data
```
## !.!@. USER
指定用于容器的用户或用户组
```Dockerfile
USER nobody
```




