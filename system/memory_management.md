<!--toc:start-->
- [内存管理浅析](#内存管理浅析)
- [节点node:struct pglist_data(别名pg_data_t)](#节点nodestruct-pglistdata别名pgdatat)
- [区域zone: struct zone](#区域zone-struct-zone)
  - [水位线](#水位线)
  - [页面](#页面)
  - [伙伴系统(buddy system)](#伙伴系统buddy-system)
- [页帧page](#页帧page)
- [页内存管理](#页内存管理)
  - [伙伴系统](#伙伴系统)
  - [页级分配API](#页级分配api)
    - [alloc_pages](#allocpages)
<!--toc:end-->

# 内存管理浅析
在很久以前的博客曾经写过slab分配，伙伴系统的分析，这里用来进行加强细节的认识和巩固知识
本次基于的内核是`linux-6.3.4`

内存由节点来表述， 而节点(zone)又划分为多个地域(zone)

     ┌──────────────────────────────────────────────┐
     │           ┌────────┬───────┬───────┬───────┐ │
     │  node     │  zone1 │ zone2 │ zone3 │ ...   │ │
     │           └────────┴───────┴───────┴───────┘ │
     └──────────────────────────────────────────────┘

# 节点node:struct pglist_data(别名pg_data_t)

用来描述内存情况,NUMA中每个node都会拥有一个这样的结构体，但是UMA中仅仅有一个

简单记录一下其中重要字段的信息:
+ `struct zone node_zones[MAX_NR_ZONES]`: 包含了当前node里面的所有zones
+ `struct zonelist node_zonelists[MAX_ZONELISTS]`: 包含了所有node的所有zones的引用
+ `int nr_zones`: 包含当前node里面被populate(激活)的zones数量
+ `unsigned long node_start_pfn`: 表示该node节点表示内存的页帧号，UMA里面始终为0,因为它只有一个节点
+ `unsigned long node_present_pages`: 表示当前node所占用的页数目


# 区域zone: struct zone
整个结构体使用宏`CACHELINE_PADDING(_pad*_);`划分成了不同的部分
这个宏主要是用来保证结构体所被划分的不同部分不会在同一个缓存行内
而这个方法是因为多处理器系统通常会有不同的CPU同时访问结构成员

## 水位线
`struct zone`下的字段，用来标注内存的水位线
```c
unsigned long _watermark[NR_WMARK];
enum zone_watermarks {
	WMARK_MIN,
	WMARK_LOW,
	WMARK_HIGH,
	WMARK_PROMO,
	NR_WMARK
};
```

1. 如果空闲页大于`_watermark[WMARK_HIGH]`,则说明zone状态理想
2. 如果空闲页低于`_watermark[WMARK_LOW]`,则内核开始将页换出到硬盘
3. 如果空闲页低于`_watermark[WMARK_MIN]`, 则说明zone急需空间，触发swapping


## 页面

这个字段则标注了每个cpu的page列表, 标注冷热页
```c
	struct per_cpu_pages	__percpu *per_cpu_pageset;
/* Fields and list protected by pagesets local_lock in page_alloc.c */
struct per_cpu_pages {
	spinlock_t lock;	/* Protects lists field */
	int count;		/* number of pages in the list */
	int high;		/* high watermark, emptying needed */
	int batch;		/* chunk size for buddy add/remove */
	short free_factor;	/* batch scaling factor during free */
#ifdef CONFIG_NUMA
	short expire;		/* When 0, remote pagesets are drained */
#endif

	/* Lists of pages, one per migrate type stored on the pcp-lists */
	struct list_head lists[NR_PCP_LISTS];
} ____cacheline_aligned_in_smp;
```


> [!NOTE]
> 每个CPU拥有一个`per_cpu_pageset`所表示的结构体`struct per_cpu_pages`
> 该结构体下拥有每个CPU的列表，用于防止多个CPU同时访问buddysystem而造成性能瓶颈



这里的`pcp-lists`

## 伙伴系统(buddy system)
用于实现伙伴系统，总共有11个order
```c

#define MAX_ORDER 11
	/* free areas of different sizes */
	struct free_area	free_area[MAX_ORDER];
```

# 页帧page
每个物理块对应一个page结构体，因此需要尽可能缩小其结构体的大小
不同类型的page他会通过`page_type`来进行标注

# 页内存管理
## 伙伴系统
用来管理空闲页
```c
struct free_area {
	struct list_head	free_list[MIGRATE_TYPES];
	unsigned long		nr_free;
};
```

`nr_free`指定当前内存区域中空闲页数量

这里的`MIGRATE_TYPES`是用来指定页面的移动类型：
```c

enum migratetype {
	MIGRATE_UNMOVABLE,
	MIGRATE_MOVABLE,
	MIGRATE_RECLAIMABLE,
	MIGRATE_PCPTYPES,	/* the number of types on the pcp lists */
	MIGRATE_HIGHATOMIC = MIGRATE_PCPTYPES,
#ifdef CONFIG_CMA
	/*
	 * MIGRATE_CMA migration type is designed to mimic the way
	 * ZONE_MOVABLE works.  Only movable pages can be allocated
	 * from MIGRATE_CMA pageblocks and page allocator never
	 * implicitly change migration type of MIGRATE_CMA pageblock.
	 *
	 * The way to use it is to change migratetype of a range of
	 * pageblocks to MIGRATE_CMA which can be done by
	 * __free_pageblock_cma() function.
	 */
	MIGRATE_CMA,
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	MIGRATE_ISOLATE,	/* can't allocate from here */
#endif
	MIGRATE_TYPES
};
```
用来防止内存空间碎片化
如果说对应某种迁移类型的页面不足与满足需求，则通过下面的数据结构来决定将使用哪种类型来进行替代
```c
/*
 * This array describes the order lists are fallen back to when

 * the free lists for the desirable migrate type are depleted
 *
 * The other migratetypes do not have fallbacks.
 */
static int fallbacks[MIGRATE_TYPES][MIGRATE_PCPTYPES - 1] = {
	[MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE   },
	[MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE },
	[MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE   },
};
```

## 页级分配API
### alloc_pages


            ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
            │                                                                                                     │
            │   alloc_pages                                                 alloc_pages_node                      │
            │       │                                                               │                             │
            │       ▼                                                               ▼                             │
            │   alloc_pages_node ──────────►__alloc_pages_node            __alloc_pages_node                      │
            │                                      │                                │                             │
            │                                      ▼                                │                             │
            │                               __alloc_pages ◄─────────────────────────┘                             │
            │                                      │                                                              │
            │               ┌──────────────────────┴─────────┬───────────────────────────────────┐                │
            │               ▼                                ▼                                   ▼                │
            │      prepare_alloc_pages             get_page_from_freelist                 alloc_pages_slowpath    │  
            │       获取zonelist信息                      分配新页面                        回收页面减轻压力      │
            │                                                 │                                分配新页面         │
            │                                                 ▼                                                   │
            │                                               rmqueue                                               │
            │                                                 │                                                   │
            │                                   ┌─────────────┴──────────────┐                                    │
            │                                   │                            │                                    │
            │                                   ▼                            ▼                                    │
            │                           rmqueue_pcplist             rmqueue_buddysystem                           │
            │                           1. 从pcp list分配              2. 从全局伙伴系统分配                      │
            └─────────────────────────────────────────────────────────────────────────────────────────────────────┘

上图就是其中分配页面的大概调用情况


### free_pages

            ┌──────────────────────────────────────────────────────────────────────────────┐
            │      free_pages                                                              │
            │          │                                                                   │
            │          ▼                                                                   │
            │     __free_pages──────────►free_the_page                                     │
            │                                │                                             │
            │                             ┌──┴──────────────────────────┐                  │
            │                             ▼                             ▼                  │
            │                   1. free_unref_page               2. __free_pages_ok        │
            │                       释放pcp page                        │                  │
            │                                                           │                  │
            │                                                           ▼                  │
            │                                                      __free_one_page         │
            │                                                        释放到buddysysstem    │
            │                                                               │              │
            │                                  find_buddy_page_pfn◄─────────┘              │
            │                                   寻找页面伙伴然后合并                       │
            └──────────────────────────────────────────────────────────────────────────────┘


## 不连续页的分配
内核使用vmalloc来分配不连续区域，分配的虚拟内存在`vmalloc/ioremap`区域
使用vmalloc的最常见的例子就是内核对于模块的实现

内核使用`struct vmstruct`来管理内存中的vmalloc区域,每个使用vmalloc分配的区域都需要有这样一个结构体来管理

### 分配API vmalloc

            ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
            │                                                                                                       │
            │      vmalloc────────►__vmalloc_node────────►__vmalloc_node_range                                      │
            │                                                  │                                                    │
            │              ┌───────────────────────────────────┴────┐                                               │
            │              ▼                                        ▼                                               │
            │     1. __get_vm_area_node                        2. __vmalloc_area_node                               │
            │      分配vm_struct                         分配物理页然后映射到vmalloc_base                           │
            │              │                                        │                                               │
            │              ├──────────────────────────┐             └──────────────────┐                            │
            │              ▼                          ▼                                ▼                            │
            │     1. alloc_vmap_area             2. setup_vmalloc_vm              vmap_pages_range                  │
            │  计算合适的分配虚拟地址空间        补全vm_struct                   将分配到的pages映射到vmalloc区域   │
            │                                                                                                       │
            └───────────────────────────────────────────────────────────────────────────────────────────────────────┘


### vfree

            ┌────────────────────────────────────────────────┐
            │           vfree                                │
            │             │                                  │
            │             │                                  │
            │             ▼                                  │
            │      remove_vm_area                            │
            │   寻找并且释放掉vmalloc分配的连续虚拟地址空间  │
            │                                                │
            └────────────────────────────────────────────────┘



# 块内存管理
主要是用于细粒度的分配，而不是以页为单位
这里主要讲解的是slub分配器
## kmalloc

                         如果分配大小大于8k
               kmalloc ─────────────►  kmalloc_large
                  │ 小于8k
                  ▼
              __kmalloc_ ─────► __do_kmalloc_node
                                      │
                     ┌────────────────┴────────────────────────┐
                     ▼                                         ▼
               1. kmalloc_slab                  2. __kmem_cache_alloc_node ───► slab_alloc_node
              到全局的kmalloc_caches中                                                │
             寻找到合适的kmem_cache                                                   │
                                                   __slab_alloc_node ◄────────────────┘
                         慢路径                    尝试直接从per-cpu cache                                  
                    ┌──────────────────────────────上的freelist直接获取object
                    │                              否则尝试慢路径
                    │
                    ▼     wrapper
             __slab_alloc────────►___slab_alloc



### 慢路径 ___slab_alloc


                ┌────────────────────────────────___slab_alloc
                │   1. 如果per-cpu cache slab为空         │
                │                                         │
                ▼                                    slab不为空
        ┌──────tag:new_slab ◄──if freelist empty─┐        │           ┌────────────► tag:load_freelist
        │          │                             │        │           │                 desc:get object
        │          │                             │        │      freelist not empty
        │   如果kmem_cache_cpu->partial还存在    │        ▼           │
        │          │                             │   tag:redo         │
        │          ▼                             │        │           │
        │   将partial链表移到slab链表            └────────┴───────────┘
        │          
    if partial empty                   ┌──►1. get_partial get partial from kmem_cache_node
        │                              │
        └────────► tag:new_objects─────┴─► 2. new_slab───────► alloc_slab_pages
                cpu preempt enable                           伙伴系统分配页面
                alloc new slab from buddy system
                cpu preempt disable
                fill the per_cpu cache->**
                


##  kfree
用来释放分配到的object

                          ┌─────────kfree
                          │
                          ▼
                 __kmem_cache_free──────────► slab_free
                                                 │
                 do_slab_free ◄──────────────────┘
                       │
                       ├─────slab !=c->slab────┐
                       │                       │
                slab == c->slab                ▼
                       │                   'slow_path'
                       ▼                   __slab_free
                 'fast_path'
            Just throw it to the freelist


### 慢路径 __slab_free
走到这里说明现在释放的slab object并不位于当前`per_cpu kmem_cache`的slab里面，



                           cpu->slab                              slab
                      ┌─────────────────┐                 ┌────────────────────┐
                      │##### data ######│                 │####################│
                      ├─────────────────┤                 ├────────────────────┤
                  ┌───┤                 │                 │####################│
                  │   ├─────────────────┤                 ├────────────────────┤
              freelist│##### data ######│                 │#### will free #####│
                  │   ├─────────────────┤                 ├────────────────────┤
                  └──►│                 ├──┐              │                    │
                      ├─────────────────┤  │              ├────────────────────┤
                      │                 │◄─┘              │####################│
                      └─────────────────┘                 └────────────────────┘


这里存在两种情况：
1. 该object存在于当前当前`per_cpu kmem_cache` 的partial链表
2. 该object既不在当前cpu的slab链表也不在partial链表

```
                                      __slab_free
                                     free object to slab      
                                               │
                 slab full    slab one         │
             if !freelist || inuse == 1 ◄──────┴─────else────┐                     dicard_slab
                     &&  was_frozen=0                        │                   free the slab to buddy sys
                       │                                     │                          ▲
                       │                                     │                ┌─────────┴──────┐
                       ├───────── else ───────────┐          ▼                │                │
                       │                          │          │          remove_partial         │
               if has cpu partial && !freelist    │          │        list_del the slab    remove_full
                       │                          │          │                ▲                ▲
                       ▼                          ▼          │                │                │
                set slab.frozen = 1         get_node         │          if prior ──────────────┘
                       │               get kmem_cache_node   │                │
                       ▼                          │          │      !new.inuse && n->nr_partial >= s->min_partial
                       ├─────────◄────────────────┘          │                │
                       └────────►─────────┬────────◄─────────┘                │
                                          │                                   │
                                     if !node ───────────else─────────────────┴────────► remove_full from kmem_cache_node
                                          │                                              add partial onto kmem_cache_node
                                          ▼
                             ┌────────────┴─────────────┐
                        if was_frozen         !was_frozen && new.frozen
                             │                          ▼
                             └────────────┐         put_cpu_partial
                                          │    put it onto the per cpu partial list
                                          ▼             │
                                       return◄──────────┘

```









