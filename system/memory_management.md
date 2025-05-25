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




        alloc_pages
            │
            ▼
        alloc_pages_node ──────────►__alloc_pages_node
                                           │
                                           ▼
                                    __alloc_pages
                                           ┃
                    ┎──────────────────────┶━━━━━━━━━┐
                    ▼                                ▼
           prepare_alloc_pages             get_page_from_freelist
            获取zonelist信息                        分配新页面   
                                                      │
                                                      ▼
                                                    rmqueue 
                                                    从buddysystem脱链



上图就是其中分配页面的大概调用情况




