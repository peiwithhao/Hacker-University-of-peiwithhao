# Common Cross cache attack
首先讲解普通的`cross cache attack`, 该攻击主要是针对于专有`kmem_cache`的利用

在Black hat 2024 asia会议中提到在传统cross cache attack中可能会遇到两种挑战：
1. 在限制分配原语的情况下，如何将victim object所在的slab置入`free_page`
2. `high-order`的slab如何复用`low-order`的slab

然后该研究员提出了一种`Advancing Cross-Cache Attack`,旨在解决上述的两种问题


## 挑战一
为了让我们的`victim object`所在的slab成功置入`free_page`,在传统的`cross cache attack`中需要分配大量的object,
并且分配完毕后还需要我们将他们保持一段时间为了之后统一收回`partial_page`当中

而对于两种需要满足的point都分别会面临一定的困难：
+ 分配大量object：
    + 专有`kmem_cache`,缓解措施有例如`CONFIG_RANDOM_KMALLOC_CACHES,AUTUSLAB`
    + 有限的系统资源
    + 内核组建的约束
+ 保持大量的object处于分配状态一段时间：
    + 临时内核对象，很快分配然后释放

拿`CVE-2023-21400`来进行举例,发现存在Double free漏洞
其中漏洞结构体为`struct npu_network_cmd`,他来自于一个专有结构体，同时在分配的过程中他也是一个临时结构体

其中提到的解决办法为使用条件竞争来将该`victim slab`释放到`free_page`
这里利用到了一种Linux的`slab`移动机制，这种原语可以将例如`cpu1`的`slab page`移动到另一个`cpu0`的`partial_page`当中
这里作为例子讲解一下其中步骤：
1. 首先一个任务需要将自己固定在cpu1上;
2. 将现在处于的slab分配满object
3. 将该任务此时固定在cpu0上
4. 此时释放刚刚分配的所有object
在我们释放第一个object的时候，这种偏离就会发生，使得之前充满的slab迁移到cpu0的`partial_page`链条当中

然后我们就可以重复上述步骤，这样就可以填满`partial_page`,然后触发链条刷新，然后将`victim slab`置入`free_page`当中
然而这个方法仍有不足，那就是我们实际上只能分配一次`victim object`然后只能维持很短的一段时间

为了解决这个问题，研究员使用一种条件竞争的方式：
1. 创建大于`OBJS_PER_SLAB`个人物TASK,这些TASK都将自己绑定在cpu1上，并且不断尝试分配`victim object`,当然分配完毕后过一小段时间就会释放
2. 然后当某一个时间点，例如满足了`OBJS_PER_SLAB`个进程都同时申请完毕,但还都没有释放，此时我们都知道cpu1上肯定存在一个slab被充满
3. 之后这些进程都会尝试释放`victim object`,但我们突然将某个进程绑定在`cpu0`,当这个进程绑定在cpu0时，由于他的释放导致这样一个slab就会链接到`cpu0`的`partial_page`当中，此时其他进程的释放也无济于事了，他们的释放也都将会在`cpu0->partial_page`当中体现
![race_binding](../img/race_binding.png)
4. 重复上述步骤我们就可以分配任意的`slab`到`partial_page`链条上

## 挑战二
由于在例子中`struct npu_network_cmd`是从order-0开始分配的，为了使用`file_array`复用该结构体， 而`file_array` 则是从order-3开始分配
为了解决这个问题需要先了解一下page分配的基本过程：
对于单个zone来说，他一般分为几个区域`unmovable, movable, reclaimable,CMA, HighAtomic, Isolate`,一般内核当中使用`alloc_pages`分配的页面位于`Unmovable`当中，
而用户空间使用`mmap`来分配的页面位于`Movable`当中

而仅仅拿`Unmovable`区域来说的话，他又被分为`per_cpu_pages/pcplist`和`free_area`部分，在我们分配`order-0`的slab的时候，一般是首先从`pcplist`当中获取,
然后后者则存放`order-0到order-10`的slab链条

那么低order如何能被高order所使用呢，唯一的可能就是当低order的slab和其物理相邻的slab均被释放时（这里实际上一个slab都通过算法对应另一个slab,所以不存在3个物理相邻则合并3个的情况）, 低order则可以合并为高order

因此想要达成这种效果，需要我们进行堆风水进行修改
1. 首先将进程绑定到cpu0
2. 分配足够的`order-0`页面，数量需要满足能够将其全部释放时能出发pcplist的刷新,而选择的结构体需要满足下面几点：
    1. 在分配的时候，需要该结构体能够被大量分配并且是从`free_area`开始分配,
    2. 在释放的时候，需要是同步的释放，这里选择到了Pipe
3. 从UNMOVABLE分配物理连续的`order-0 pages`
4. 







# 调试slab
可使用`slabtop`命令

# 配置释义
+ `CONFIG_RANDOM_KMALLOC_CACHES`:从4.14.327开始，对于正常的kmalloc的分配创建多个`slab cache`的副本，kmalloc会根据代码在其中随机选择一个,现在副本数量默认设置为16

[config释义](https://www.kernelconfig.io/index.html)




