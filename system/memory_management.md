# 内存管理浅析
在很久以前的博客曾经写过slab分配，伙伴系统的分析，这里用来进行加强细节的认识和巩固知识
本次基于的内核是`linux-6.3.4`

内存由节点来表述， 而节点(zone)又划分为多个地域(zone)






# node:struct pglist_data(别名pg_data_t)

用来描述内存情况,NUMA中每个node都会拥有一个这样的结构体，但是UMA中仅仅有一个

简单记录一下其中重要字段的信息:
+ `struct zone node_zones[MAX_NR_ZONES]`: 包含了当前node里面的所有zones
+ `struct zonelist node_zonelists[MAX_ZONELISTS]`: 包含了所有node的所有zones的引用
+ `int nr_zones`: 包含当前node里面被populate(激活)的zones数量
+ `unsigned long node_start_pfn`: 表示该node节点表示内存的页帧号，UMA里面始终为0,因为它只有一个节点
+ `unsigned long node_present_pages`: 表示当前node所占用的页数目


# zone: struct zone
整个结构体使用宏`CACHELINE_PADDING(_pad*_);`划分成了不同的部分
这个宏主要是用来保证结构体所被划分的不同部分不会在同一个缓存行内







