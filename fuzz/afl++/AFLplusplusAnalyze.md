<!--toc:start-->
- [afl-cc](#afl-cc)
- [afl-fuzz](#afl-fuzz)
  - [core struct](#core-struct)
    - [struct afl_state](#struct-aflstate)
    - [struct afl_forkserver](#struct-aflforkserver)
  - [setup_signal_handlers()](#setupsignalhandlers)
  - [check_asan_opts](#checkasanopts)
  - [fix_up_sync](#fixupsync)
  - [afl_realloc](#aflrealloc)
  - [save_cmdline](#savecmdline)
  - [check_if_tty](#checkiftty)
  - [get_core_count](#getcorecount)
  - [atexit](#atexit)
  - [setup_dirs_fds](#setupdirsfds)
  - [bind_to_free_cpu](#bindtofreecpu)
  - [init_count_class16](#initcountclass16)
  - [setup_custom_mutators](#setupcustommutators)
    - [mutator library](#mutator-library)
    - [python module](#python-module)
  - [setup_cmdline_file](#setupcmdlinefile)
  - [check_binary](#checkbinary)
  - [write_setup_file](#writesetupfile)
  - [read_testcases](#readtestcases)
  - [add_to_queue](#addtoqueue)
    - [struct queue_entry](#struct-queueentry)
  - [pivot_inputs](#pivotinputs)
  - [setup_stdio_file](#setupstdiofile)
  - [setup_testcase_shmem](#setuptestcaseshmem)
  - [afl_shm_init](#aflshminit)
- [FAST(exponential)](#fastexponential)
- [COE(cut-off exponential)](#coecut-off-exponential)
- [LIN(linear)](#linlinear)
- [QUAD(quadratic)](#quadquadratic)
- [MMOPT(modified M0pt)](#mmoptmodified-m0pt)
- [RARE(rare edge focus)](#rarerare-edge-focus)
- [SEEK(seek)](#seekseek)
- [EXPLORE(exploration-based constant)](#exploreexploration-based-constant)
<!--toc:end-->
# ---- fuzzer 编译 ----
# afl-cc.c
首先介绍一下在afl-cc.c函数里面所涉及到的关键结构体
```c
typedef struct aflcc_state {

  u8 **cc_params;                      /* Parameters passed to the real CC  */
  u32  cc_par_cnt;                     /* Param count, including argv0      */

  u8 *argv0;                           /* Original argv0 (by strdup)        */
  u8 *callname;                        /* Executable file argv0 indicated   */

  u8 debug;

  u8 compiler_mode, plusplus_mode, lto_mode;

  u8 *lto_flag;

  u8 instrument_mode, instrument_opt_mode, ngram_size, ctx_k;

  u8 cmplog_mode;

  u8 have_instr_env, have_gcc, have_clang, have_llvm, have_gcc_plugin, have_lto,
      have_optimized_pcguard, have_instr_list;

  u8 fortify_set, x_set, bit_mode, preprocessor_only, have_unroll, have_o,
      have_pic, have_c, shared_linking, partial_linking, non_dash, have_fp,
      have_flto, have_hidden, have_fortify, have_fcf, have_staticasan,
      have_rust_asanrt, have_asan, have_msan, have_ubsan, have_lsan, have_tsan,
      have_cfisan;

  // u8 *march_opt;
  u8  need_aflpplib;
  int passthrough;

  u8  use_stdin;                                                   /* dummy */
  u8 *argvnull;                                                    /* dummy */

} aflcc_state_t;
```


首先查看main函数的整体结构可以得知我们的整个操作就是丰富上面的结构体,然后执行命令行
```c
/* Main entry point */
int main(int argc, char **argv, char **envp) {

    //分配struct aflcc_state
  aflcc_state_t *aflcc = malloc(sizeof(aflcc_state_t));
    //根据传递参数初始化aflcc_state
  aflcc_state_init(aflcc, (u8 *)argv[0]);
    ...
  edit_params(aflcc, argc, argv, envp);

  if (aflcc->debug)
    debugf_args((s32)aflcc->cc_par_cnt, (char **)aflcc->cc_params);

  if (aflcc->passthrough) {

    argv[0] = aflcc->cc_params[0];
    execvp(aflcc->cc_params[0], (char **)argv);

  } else {

    execvp(aflcc->cc_params[0], (char **)aflcc->cc_params);

  }

    ....
}
```
这里简单解释一下,该代码是一层对于你给出的选项进行编译的wrapper, 实际上仍然是使用gcc或者是clang进行编译,所以涉及到编译的信息时再进行详细描述
我们平时采用的`afl-clang-fast`等编译指令,实际上都是对于该c代码所编译形成的elf的符号链接,而该elf则会根据你传递的第一个参数来进一步设置编译选项`argv[0]`

# ---- fuzzer插桩 ----
# afl-as.c
这里为编译时插桩


# ---- fuzzer前期准备 ----
前期主要是做了一些afl字段的填充,测试用例的初始化, 输出输入目录处理, forkserver的创建等操作

# afl-fuzz.c
# core struct

这里介绍两个重要的结构体

## struct afl_state
同样这里我们需要先简单看一下该afl-fuzz的c代码所涉及到的关键结构体`afl_state_t`
```c
typedef struct afl_state {

  /* 全局状态列表中状态所处位置 */
  u32 _id;

  afl_forkserver_t fsrv;        /* afl创建子进程的服务结构体 */
  sharedmem_t      shm;
  sharedmem_t     *shm_fuzz;
  afl_env_vars_t   afl_env;

  char **argv;                                            /* argv if needed */

  /* MOpt:
    Lots of globals, but mostly for the status UI and other things where it
    really makes no sense to haul them around as function parameters. */
/* 优化参数: 大部分全局, 但是大多数是用于状态UI和其他真正没有意义的事物作为函数参数 */
  u64 orig_hit_cnt_puppet, last_limit_time_start, tmp_pilot_time,
      total_pacemaker_time, total_puppet_find, temp_puppet_find, most_time_key,
      most_time, most_execs_key, most_execs, old_hit_count, force_ui_update,
      prev_run_time;

  MOpt_globals_t mopt_globals_core, mopt_globals_pilot;
    ....

  u8 *in_dir,                           /* 测试样例的输入目录               */
      *out_dir,                         /* 工作目录&输出目录                */
      *tmp_dir,                         /* 输入的临时目录                   */
      *sync_dir,                        /* 同步目录                         */
      *sync_id,                         /* Fuzzer ID                        */
      *power_name,                      /* Power schedule 名称              */
      *use_banner,                      /* 展示标识                         */
      *in_bitmap,                       /* 输入位图                         */
      *file_extension,                  /* 文件扩展                         */
      *orig_cmdline,                    /* 原始命令                         */
      *infoexec;                       /* 当出现一个新的crash时所执行的指令 */

  u32 hang_tmout,                       /* 用于挂起的超时时间限定范围(ms)   */
      stats_update_freq;                /* 统计更新频率 (execs)   */

    .....

  u32 queued_items,                     /* 队列测试样例的总数               */
      queued_variable,                  /* 具有可变行为的测试样例 */
      queued_at_start,                  /* 初始化输入的总数  */
      queued_discovered,                /* 在此次运行过程中未发现的条目 */
      queued_imported,                  /* 通过-S来导入的Items            */
      queued_favored,                   /* 被视为喜爱的路径          */
      queued_with_cov,                  /* 有着新覆盖率字节的路径    */
      pending_not_fuzzed,               /* 已经排队但未完成          */
      pending_favored,                  /* 待定的首选路径            */
      cur_skipped_items,                /* 在当前循环中抛弃的输入   */
      cur_depth,                        /* 当前路径深度           */
      max_depth,                        /* 最大路径深度                   */
      useless_at_start,                 /* 没用的启动路径数目 */
      var_byte_count,                   /* 有着可变行为的位图字节 */
      current_entry,                    /* 当前队列条目           */
      havoc_div,                        /* 循环计数分割线破坏    */
      max_det_extras;                   /*  确定性额外计数(dicts)*/

  u64 total_crashes,                    /* crash的总数          */
      saved_crashes,                    /* 拥有唯一签名的crash总数  */
      total_tmouts,                     /* 超时的总数         */
      saved_tmouts,                     /* 拥有唯一签名的超市数量 */
      saved_hangs,                      /* 拥有唯一签名的刮起     */
      last_crash_execs,                 /* 上次崩溃时的执行计数器       */
      queue_cycle,                      /* Queue round counter              */
      cycles_wo_finds,                  /* Cycles without any new paths     */
      trim_execs,                       /* Execs done to trim input files   */
      bytes_trim_in,                    /* Bytes coming into the trimmer    */
      bytes_trim_out,                   /* Bytes coming outa the trimmer    */
      blocks_eff_total,                 /* Blocks subject to effector maps  */
      blocks_eff_select,                /* Blocks selected as fuzzable      */
      start_time,                       /* Unix start time (ms)             */
      last_sync_time,                   /* Time of last sync                */
      last_sync_cycle,                  /* Cycle no. of the last sync       */
      last_find_time,                   /* Time for most recent path (ms)   */
      last_crash_time,                  /* Time for most recent crash (ms)  */
      last_hang_time,                   /* Time for most recent hang (ms)   */
      longest_find_time,                /* Longest time taken for a find    */
      exit_on_time,                     /* Delay to exit if no new paths    */
      sync_time,                        /* Sync time (ms)                   */
      switch_fuzz_mode,                 /* auto or fixed fuzz mode          */
      calibration_time_us,              /* Time spend on calibration        */
      sync_time_us,                     /* Time spend on sync               */
      cmplog_time_us,                   /* Time spend on cmplog             */
      trim_time_us;                     /* Time spend on trimming           */

  u32 slowest_exec_ms,                  /* Slowest testcase non hang in ms  */
      subseq_tmouts;                    /* Number of timeouts in a row      */

  u8 *stage_name,                       /* Name of the current fuzz stage   */
      *stage_short,                     /* Short stage name                 */
      *syncing_party;                   /* Currently syncing with...        */

  u8 stage_name_buf[STAGE_BUF_SIZE];    /* reused stagename buf with len 64 */

  u32 stage_cur, stage_max;             /* Stage progression                */
  s32 splicing_with;                    /* Splicing with which test case?   */
  s64 smallest_favored;                 /* smallest queue id favored        */

  u32 main_node_id, main_node_max;      /*   Main instance job splitting    */

  u32 syncing_case;                     /* Syncing with case #...           */

  s32 stage_cur_byte,                   /* Byte offset of current stage op  */
      stage_cur_val;                    /* Value used for stage op          */

  u8 stage_val_type;                    /* Value type (STAGE_VAL_*)         */

  u64 stage_finds[32],                  /* Patterns found per fuzz stage    */
      stage_cycles[32];                 /* Execs per fuzz stage             */

  u32 rand_cnt;                         /* Random number counter            */

  /*  unsigned long rand_seed[3]; would also work */
  AFL_RAND_RETURN rand_seed[3];
  s64             init_seed;

  u64 total_cal_us,                     /* Total calibration time (us)      */
      total_cal_cycles;                 /* Total calibration cycles         */

  u64 total_bitmap_size,                /* Total bit count for all bitmaps  */
      total_bitmap_entries;             /* Number of bitmaps counted        */

  s32 cpu_core_count,                   /* CPU 核心数量                   */
      cpu_to_bind;                      /* 绑定指定的CPU             */

#ifdef HAVE_AFFINITY
  s32 cpu_aff;                          /* 选择的CPU核心              */
#endif                                                     /* 有亲和性HAVE_AFFINITY */

  struct queue_entry *queue,            /* fuzzing队列 (linked list)      */
      *queue_cur,                       /* 队列中的当前偏移量 */
      *queue_top;                       /* 当前列表的top                 */

  // 增长缓冲区
  struct queue_entry **queue_buf;

  struct queue_entry **top_rated;           /* Top entries for bitmap bytes */

  struct extra_data *extras;            /* Extra tokens to fuzz with        */
  u32                extras_cnt;        /* Total number of tokens read      */

  struct auto_extra_data
      a_extras[MAX_AUTO_EXTRAS];        /* Automatically selected extras    */
  u32 a_extras_cnt;                     /* Total number of tokens available */

  /* afl_postprocess API - Now supported via custom mutators */

  /* CmpLog */

  char            *cmplog_binary;
  afl_forkserver_t cmplog_fsrv;     /* cmplog has its own little forkserver */

  /* Custom mutators */
  struct custom_mutator *mutator;

  /* cmplog forkserver ids */
  s32 cmplog_fsrv_ctl_fd, cmplog_fsrv_st_fd;
  u32 cmplog_prev_timed_out;
  u32 cmplog_max_filesize;
  u32 cmplog_lvl;
  u32 colorize_success;
  u8  cmplog_enable_arith, cmplog_enable_transform, cmplog_enable_scale,
      cmplog_enable_xtreme_transform, cmplog_random_colorization;

  struct afl_pass_stat *pass_stats;
  struct cmp_map       *orig_cmp_map;

  u8 describe_op_buf_256[256]; /* describe_op will use this to return a string
                                  up to 256 */

  unsigned long long int last_avg_exec_update;
  u32                    last_avg_execs;
  double                 last_avg_execs_saved;

/* foreign sync */
#define FOREIGN_SYNCS_MAX 32U
  u8                  foreign_sync_cnt;
  struct foreign_sync foreign_syncs[FOREIGN_SYNCS_MAX];

#ifdef _AFL_DOCUMENT_MUTATIONS
  u8  do_document;
  u32 document_counter;
#endif

  /* statistics file */
  double last_bitmap_cvg, last_stability, last_eps;
  u64    stats_file_update_freq_msecs;  /* Stats update frequency (msecs)   */

  /* plot file saves from last run */
  u32 plot_prev_qp, plot_prev_pf, plot_prev_pnf, plot_prev_ce, plot_prev_md;
  u64 plot_prev_qc, plot_prev_uc, plot_prev_uh, plot_prev_ed;

  u64 stats_last_stats_ms, stats_last_plot_ms, stats_last_queue_ms,
      stats_last_ms, stats_last_execs;

  /* StatsD */
  u64                statsd_last_send_ms;
  struct sockaddr_in statsd_server;
  int                statsd_sock;
  char              *statsd_tags_flavor;
  char              *statsd_tags_format;
  char              *statsd_metric_format;
  int                statsd_metric_format_type;

  double stats_avg_exec;

  u8 *clean_trace;
  u8 *clean_trace_custom;
  u8 *first_trace;

  /* needed for afl_fuzz_one */
  // TODO: see which we can reuse
  u8 *out_buf;

  u8 *out_scratch_buf;

  u8 *eff_buf;

  u8 *in_buf;

  u8 *in_scratch_buf;

  u8 *ex_buf;

  u8 *testcase_buf, *splicecase_buf;

  u32 custom_mutators_count;

  struct custom_mutator *current_custom_fuzz;

  list_t custom_mutator_list;

  /* this is a fixed buffer of size map_size that can be used by any function if
   * they do not call another function */
  u8 *map_tmp_buf;

  /* queue entries ready for splicing count (len > 4) */
  u32 ready_for_splicing_count;

  /* min/max length for generated fuzzing inputs */
  u32 min_length, max_length;

  /* This is the user specified maximum size to use for the testcase cache */
  u64 q_testcase_max_cache_size;

  /* This is the user specified maximum entries in the testcase cache */
  u32 q_testcase_max_cache_entries;

  /* How much of the testcase cache is used so far */
  u64 q_testcase_cache_size;

  /* highest cache count so far */
  u32 q_testcase_max_cache_count;

  /* How many queue entries currently have cached testcases */
  u32 q_testcase_cache_count;

  /* the smallest id currently known free entry */
  u32 q_testcase_smallest_free;

  /* How often did we evict from the cache (for statistics only) */
  u32 q_testcase_evictions;

  /* Refs to each queue entry with cached testcase (for eviction, if cache_count
   * is too large) */
  struct queue_entry **q_testcase_cache;

  /* Global Profile Data for deterministic/havoc-splice stage */
  struct havoc_profile *havoc_prof;

  struct skipdet_global *skipdet_g;

#ifdef INTROSPECTION
  char  mutation[8072];
  char  m_tmp[4096];
  FILE *introspection_file;
  u32   bitsmap_size;
#endif

} afl_state_t;
```

## struct afl_forkserver
然后就是`afl_forkserver_t`

```c
typedef struct afl_forkserver {

    /* 包含afl-forkserver的程序需要定义这些字段 */

  u8 *trace_bits;                       /* 有着插桩位图的SHM */

  s32 fsrv_pid,                         /* fork服务的PID           */
      child_pid,                        /* fuzzed程序的PID        */
      child_status,                     /* 子进程返回给fork服务器的waitped status    */
      out_dir_fd;                       /* 被锁文件的FD             */

  s32 out_fd,                           /* fsrv->out_file的持久化fd */
      dev_urandom_fd,                   /* /dev/urandom 的持久化fd  */

      dev_null_fd,                      /* /dev/null 的持久化fd     */
      fsrv_ctl_fd,                      /* Fork server 的控制 pipe (write) */
      fsrv_st_fd;                       /* Fork server 的status pipe (read)   */

  u32 exec_tmout;                       /* 可配置的执行超时(ms)  */
  u32 init_tmout;                       /* 可配置的初始超时(ms)   */
  u32 map_size;                         /* 被目标所使用的map 大小    */
  u32 real_map_size;                    /* real map size, unaligned         */
  u32 snapshot;                         /* is snapshot feature used         */
  u64 mem_limit;                        /* 子进程的内存cap (MB)        */

  u64 total_execs;                      /* How often run_target was called  */

  u8 *out_file,                         /* 需要被fuzz的文件, 如果有的话             */
      *target_path;                     /* 目标路径               */

  FILE *plot_file,                      /* Gnuplot output file              */
      *det_plot_file;

  /* Note: last_run_timed_out is u32 to send it to the child as 4 byte array */
  u32 last_run_timed_out;               /* 被追踪的程序是否超时       */

  u8 last_kill_signal;                  /* 杀掉子进程的信号     */

  bool use_shmem_fuzz;                  /* 对测试用例使用共享内存   */

  bool support_shmem_fuzz;              /* 通过afl-fuzz设置                  */

  bool use_fauxsrv;                     /* Fauxsrv 用于非分叉目标 */

  bool qemu_mode;                       /* 是否运行在qemu 模式 */

  bool frida_mode;                     /* if running in frida mode or not   */

  bool frida_asan;                    /* if running with asan in frida mode */

  bool cs_mode;                      /* if running in CoreSight mode or not */

  bool use_stdin;                       /* use stdin for sending data       */

  bool no_unlink;                       /* 不要unlink cur_input       */

  bool uses_asan;                       /* 目标是否使用ASAN               */

  bool debug;                           /* 是否使用debug模式                      */

  bool uses_crash_exitcode;             /* Custom crash exitcode specified? */
  u8   crash_exitcode;                  /* The crash exitcode specified     */

  u32 *shmem_fuzz_len;                  /* length of the fuzzing test case  */

  u8 *shmem_fuzz;                       /* 为了fuzzing所分配的内存   */

  char *cmplog_binary;                  /* cmplog二进制的名称  */

  /* persistent mode replay functionality */
  u32 persistent_record;                /* persistent replay setting        */
#ifdef AFL_PERSISTENT_RECORD
  u32  persistent_record_idx;           /* persistent replay cache ptr      */
  u32  persistent_record_cnt;           /* persistent replay counter        */
  u8  *persistent_record_dir;
  u8 **persistent_record_data;
  u32 *persistent_record_len;
  s32  persistent_record_pid;
#endif

    /* 启动forkserver子进程的函数 */
  void (*init_child_func)(struct afl_forkserver *fsrv, char **argv);

  u8 *afl_ptr;                          /* 自动字典: afl ptr      */

  void (*add_extra_func)(void *afl_ptr, u8 *mem, u32 len);

  u8 child_kill_signal;
  u8 fsrv_kill_signal;

  u8 persistent_mode;

  u32 max_length;

#ifdef __linux__
  nyx_plugin_handler_t *nyx_handlers;
  char                 *out_dir_path;    /* path to the output directory     */
  u8                    nyx_mode;        /* if running in nyx mode or not    */
  bool                  nyx_parent;      /* create initial snapshot          */
  bool                  nyx_standalone;  /* don't serialize the snapshot     */
  void                 *nyx_runner;      /* nyx runner object                */
  u32                   nyx_id;          /* nyx runner id (0 -> master)      */
  u32                   nyx_bind_cpu_id; /* nyx runner cpu id                */
  char                 *nyx_aux_string;
  u32                   nyx_aux_string_len;
  bool                  nyx_use_tmp_workdir;
  char                 *nyx_tmp_workdir_path;
  s32                   nyx_log_fd;
  u64                   nyx_target_hash64;
#endif

#ifdef __AFL_CODE_COVERAGE
  u8 *persistent_trace_bits;                   /* Persistent copy of bitmap */
#endif

  void *custom_data_ptr;
  u8   *custom_input;
  u32   custom_input_len;
  void (*late_send)(void *, const u8 *, size_t);

} afl_forkserver_t;
```



这里就是fuzz的主体,首先查看main函数

```c
/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  ...

/* 获取参数数组 */
  char **argv = argv_cpy_dup(argc, argv_orig);

/* 分配afl结构体 */
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  if (!afl) { FATAL("Could not create afl state"); }

  if (get_afl_env("AFL_DEBUG")) { debug = afl->debug = 1; }

/* 初始化afl_state */
  afl_state_init(afl, map_size);
  afl->debug = debug;
/* 初始化afl的fork服务器配置 */
  afl_fsrv_init(&afl->fsrv);
  if (debug) { afl->fsrv.debug = true; }
/* 通过环境变量来设置afl_state字段 */
  read_afl_environment(afl, envp);
/* 通过共享内存的映射大小来设置fork server的的大小 */
  if (afl->shm.map_size) { afl->fsrv.map_size = afl->shm.map_size; }
  exit_1 = !!afl->afl_env.afl_bench_just_one;

  SAYF(cCYA "afl-fuzz" VERSION cRST
            " based on afl by Michal Zalewski and a large online community\n");

/* 获取当前时间, tv存放时间, tz存放时区 */
  gettimeofday(&tv, &tz);
/* 设置初始种子为我们的Unix纪元的秒数异或微秒数再异或该进程的pid
 * 然后设置随机种子,
 * 第一项为取hash值,   
 * 第二项为异或某个奇怪的数字
 * 第三项为与的一个奇怪数字得出的值和或一个奇怪数组得出的值两者进行异或
 */
  rand_set_seed(afl, tv.tv_sec ^ tv.tv_usec ^ getpid());

/* 执行共享内存fuzz模式 */
  afl->shmem_testcase_mode = 1;  // we always try to perform shmem fuzzing
....
```


# afl_fsrv_init
初始化了一些`afl->fsrv`的参数以及其子进程处理函数


截至目前是完成了初始种子的赋值,对于种子的设置可以查看下面内容


```c
void rand_set_seed(afl_state_t *afl, s64 init_seed) {

  afl->init_seed = init_seed;
  afl->rand_seed[0] =
      hash64((u8 *)&afl->init_seed, sizeof(afl->init_seed), HASH_CONST);
  afl->rand_seed[1] = afl->rand_seed[0] ^ 0x1234567890abcdef;
  afl->rand_seed[2] = (afl->rand_seed[0] & 0x1234567890abcdef) ^
                      (afl->rand_seed[1] | 0xfedcba9876543210);

}
```
之后afl-fuzz的main需要根据我们传递的参数来设置fuzz模式

```c
  // still available: HjJkKqruvwz
  while ((opt = getopt(argc, argv,
                       "+a:Ab:B:c:CdDe:E:f:F:g:G:hi:I:l:L:m:M:nNo:Op:P:QRs:S:t:"
                       "T:UV:WXx:YzZ")) > 0) {
    switch (opt) {

      case 'a':

        if (!stricmp(optarg, "text") || !stricmp(optarg, "ascii") ||
            !stricmp(optarg, "txt") || !stricmp(optarg, "asc")) {
   ..... 
```
这里来解释一下各自的含义

+ a:不区分大小写,设置`afl->input_mode`
+ P:不区分大小写,设置`afl->fuzz_mode, afl->switch_fuzz_mode`
+ g:设置min_length
+ G:设置max_length
+ Z:set old_seed_selection
+ I:set infoexec
+ b:bind CPU core, has to be a %d
+ c:set shm.cmplog_mode, cmplog_binary
+ s:set intial_seed, fixed_seed
+ p:set Power scheduler
+ e:set file_extension, multiple can not be
+ i:set in_dir
+ o:set out_dir
+ M:set main sync ID
+ S:set secondary sync id
+ F:set foreign sync dir
+ f:设置目标fuzz文件, fsrv.out_file
+ x:set dictionary 
+ t:set timeout 
+ m:set mem limit, fsrv.mem_limit
+ d, D:nothing
+ z:set skip_deterministic
+ B:这是一个不存在于文档记录的选项,如果你在一次普通的fuzzing程序中找到一个有趣的测试样例并且想要不重新发现早期运行期间已经发现的任何测试用例来进行变异,这个选项能派上用场, 
+ C:set crash mode, crash_mode
+ n:set dumb mode, is_main_node, is_secondary_node, non_instrumented_mode
+ T:set banner, use_banner
+ X:set NYX mode, fsrv.nyx_parent, fsrv.nyx_standalone, fsrv.nyx_mode, fsrv.nyx_id
+ Y:set NYX distributed mode, fsrv.nyx_mode
+ A:set CoreSight mode, fsrv_cs.mode 
+ O:set FRIDA mode, fsrv.frida_mode
+ Q:set QEMU mode, fsrv.qemu_mode
+ N:set fsrv.no_unlink
+ U:set unicorn mode, unicorn_mode
+ W:set Wine+QEMU mode, fsrv.qemu_mode, use_wine, fsrv.mem_limit 
+ V:most_time_key
+ E:most_execs_key
+ l:set log level
+ L:set M0pt mode, havoc_max_mult, limit_time_*
+ h:show help

# setup_signal_handlers()
该函数用来设置信号处理函数
```c
#define	SIG_ERR	 ((__sighandler_t) -1)	/* Error return.  */
#define	SIG_DFL	 ((__sighandler_t)  0)	/* Default action.  */
#define	SIG_IGN	 ((__sighandler_t)  1)	/* Ignore signal.  */
```

其中分别对应的信号和函数如下:
+ SIGHUP:handle_stop_sig
+ SIGINT:handle_stop_sig
+ SIGTERM:handle_stop_sig
+ SIGWITCH:handle_resize
+ SIGUSR1:handle_skipreq
+ SIGTSTP:SIG_IGN
+ SIGPIPE:SIG_IGN

# check_asan_opts
读取环境变量`ASAN_OPTIONS, MSAN_OPTIONS`,然后做相应检查
```c
void check_asan_opts(afl_state_t *afl) {

  u8 *x = get_afl_env("ASAN_OPTIONS");

  .....
  x = get_afl_env("MSAN_OPTIONS");
  ...
```

# fix_up_sync
这个函数主要是为了使得`afl->out_dir`和当使用-S时的`sync_dir`有效化
新配置out_dir和sync_dir

下面介绍几种调度器类型
```c
enum {

  /* 00 */ EXPLORE, /* AFL default, Exploration-based constant schedule */
  /* 01 */ MMOPT,   /* Modified MOPT schedule           */
  /* 02 */ EXPLOIT, /* AFL's exploitation-based const.  */
  /* 03 */ FAST,    /* Exponential schedule             */
  /* 04 */ COE,     /* Cut-Off Exponential schedule     */
  /* 05 */ LIN,     /* Linear schedule                  */
  /* 06 */ QUAD,    /* Quadratic schedule               */
  /* 07 */ RARE,    /* Rare edges                       */
  /* 08 */ SEEK,    /* EXPLORE that ignores timings     */

  POWER_SCHEDULES_NUM

};
```
如果调度器范围位于[FAST, RARE], 则动态的为调度器分配内存
```c
  /* Dynamically allocate memory for AFLFast schedules */
  if (afl->schedule >= FAST && afl->schedule <= RARE) {

    afl->n_fuzz = ck_alloc(N_FUZZ_SIZE * sizeof(u32));

  }
```
这之后便是一系列通过传递的环境变量来设置afl_state数据结构体标识位
例如:
```c
  if (afl->afl_env.afl_exit_on_time) {

    u64 exit_on_time = atoi(afl->afl_env.afl_exit_on_time);
    afl->exit_on_time = (u64)exit_on_time * 1000;

  }
```
然后是分配一系列缓冲区
```c
  OKF("Generating fuzz data with a length of min=%u max=%u", afl->min_length,
      afl->max_length);
  u32 min_alloc = MAX(64U, afl->min_length);
  afl_realloc(AFL_BUF_PARAM(in_scratch), min_alloc);
  afl_realloc(AFL_BUF_PARAM(in), min_alloc);
  afl_realloc(AFL_BUF_PARAM(out_scratch), min_alloc);
  afl_realloc(AFL_BUF_PARAM(out), min_alloc);
  afl_realloc(AFL_BUF_PARAM(eff), min_alloc);
  afl_realloc(AFL_BUF_PARAM(ex), min_alloc);
```
# afl_realloc
该函数确保调用后 size > size_needed。否则它将重新分配buf
```c
  ...
  u8 *out_buf;

  u8 *out_scratch_buf;

  u8 *eff_buf;

  u8 *in_buf;

  u8 *in_scratch_buf;

  u8 *ex_buf;

  u8 *testcase_buf, *splicecase_buf;
  ...
```
# save_cmdline
复制当前指令行
```c
...
  buf = afl->orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; ++i) {

    u32 l = strlen(argv[i]);

    if (!argv[i] || !buf) { FATAL("null deref detected"); }

    memcpy(buf, argv[i], l);
    buf += l;
...
```

# check_if_tty
检查是否在TTY上面,如果说设置了`afl_no_ui`环境变量,则设置相应afl的字段
如果没有设置这个环境变量且检查是在tty上`ioctl(1, TIOCGWINSZ, &ws)`,则报错

# get_core_count
计算逻辑CPU核心的数量

# atexit
这里是注册当exit被调用时需要执行的函数`at_exit()`,这里函数主要是执行杀掉相关进程,通过共享内存ID回收共享内存等等

# setup_dirs_fds
创建output的相关目录
和获取一些必要的文件fd,例如`afl->fsrv`的`/dev/null && /dev/urandom`

# bind_to_free_cpu
如果有对于CPU亲和性的要求那么执行该函数,
该函数建立一个绑定指定核心的进程列表
# init_count_class16
```c
u16 count_class_lookup16[65536];

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}
```
这里是初始化了`count_class_lookup16`的一个全局数组,该数组定义在`afl-fuzz-bitmap.c`当中

# setup_custom_mutators
该函数负责获取`struct custom_mutator *mutator`
## mutator library 

首先尝试有没有变异库
```c
void setup_custom_mutators(afl_state_t *afl) {

  /* Try mutator library first */
  struct custom_mutator *mutator;
  u8                    *fn = afl->afl_env.afl_custom_mutator_library;
  u32                    prev_mutator_count = 0;

  if (fn) {
...
      mutator = load_custom_mutator(afl, fn);
      list_append(&afl->custom_mutator_list, mutator);
...

```
如果有的话则从库中加载`afl_custom_init, afl_custom_fuzz, afl_custom_mtator`等符号,然后将地址传给mutator, 然后将其挂到`afl->custom_mutator_list`这个链表上面,然后相应计数+1


## python module

```c
  /* Try Python module */
#ifdef USE_PYTHON
  u8 *module_name = afl->afl_env.afl_python_module;
  ...
    struct custom_mutator *m = load_custom_mutator_py(afl, module_name);
    afl->custom_mutators_count++;
    list_append(&afl->custom_mutator_list, m);
  ...
```

然后尝试python模块, 如果获取到了模块名
则我们同样需要新创建一个mutator,然后挂上相同链表

# setup_cmdline_file
缓存我们的指令还来重现我们的发现
这里主要是将argv[i]以行的形式写入我们的`/out/default/cmdline`文件

# check_binary
检查目标二进制文件是否存在,然后检查他是否是一个shell脚本

# write_setup_file
写fuzzer_setup,这个文件也是位于`out/default`目录下
这个文件打开的例子如下,
```sh
# environment variables:
AFL_CUSTOM_INFO_PROGRAM=/home/fuzzing_libexif/install/bin/exif
AFL_CUSTOM_INFO_PROGRAM_ARGV=@@
AFL_CUSTOM_INFO_OUT=/home/fuzzing_libexif/out//default
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
AFL_TRY_AFFINITY=1
AFL_SKIP_CPUFREQ=1
# command line:
'afl-fuzz' '-i' '/home/fuzzing_libexif/exif-samples-master/jpg/' '-o' '/home/fuzzing_libexif/out/' '-s' '123' '--' '/home/fuzzing_libexif/install/bin/exif' '@@'
```
# read_testcases
从输入目录读取所有的测试用例, 然后将他们进行排队测试, 在开始时调用
这里使用`scandir()+alphasort()`而不是`readdir()`的原因是后者可能造成测试样例顺序的紊乱导致难以控制

首先是扫描`in_dir/queue`目录是否存在,如果不存在则仅仅扫描 `indir`
然后开始扫描输入目录,这里`scandir`搭配的`alphasort`是一个排序函数,用来按照字母顺序来存放目录项

其中的&nl是一个指向 `struct dirent **` 类型的指针的地址。`scandir`函数会分配内存并填充这个指针，指向一个包含目录项的结构体数组。每个结构体代表一个文件或子目录。

# add_to_queue
将新的测试样例添加到队列,每个队列元素为`struct queue_entry`
## struct queue_entry
```c
struct queue_entry {

  u8 *fname;                            /* 测试样例的文件名      */
  u32 len;                              /* 输入长度 */
  u32 id;                               /* 在queue_buf中的index    */

  u8 colorized,                         /* Do not run redqueen stage again  */
      cal_failed;                       /* 校准是否失败      */

  bool trim_done,                       /* 是否被修剪         */
      was_fuzzed,                       /* historical, but needed for MOpt  */
      passed_det,                       /* 确定性阶段已过?     */
      has_new_cov,                      /* 是否出发新的覆盖率 */
      var_behavior,                     /* Variable behavior?      */
      favored,                          /* 现在是否被喜爱       */
      fs_redundant,                     /* Marked as redundant in the fs?   */
      is_ascii,                         /* 输入是否仅为ASCII文本   */
      disabled;                         /* Is disabled from fuzz selection  */

  u32 bitmap_size,                      /* Number of bits set in bitmap     */
#ifdef INTROSPECTION
      stats_selected,                   /* stats: how often selected        */
      stats_skipped,                    /* stats: how often skipped         */
      stats_finds,                      /* stats: # of saved finds          */
      stats_crashes,                    /* stats: # of saved crashes        */
      stats_tmouts,                     /* stats: # of saved timeouts       */
#endif
      fuzz_level,                       /* Number of fuzzing iterations     */
      n_fuzz_entry;                     /* offset in n_fuzz                 */

  u64 exec_us,                          /* 执行时间(us)         */
      handicap,                         /* Number of queue cycles behind    */
      depth,                            /* 路径深度                       */
      exec_cksum,                       /* Checksum of the execution trace  */
      custom,                           /* Marker for custom mutators       */
      stats_mutated;                    /* stats: # of mutations performed  */

  u32 tc_ref;                           /* Trace bytes ref count            */

#ifdef INTROSPECTION
  u32 bitsmap_size;
#endif

  double perf_score,                    /*  表现得分             */
      weight;

  struct queue_entry *mother;            /* queue entry this based on        */
  u8                 *trace_mini;        /* 追踪的字节            */
  u8                 *testcase_buf;      /* 测试样例的缓冲区if loaded.  */
  u8                 *cmplog_colorinput; /* the result buf of colorization   */
  struct tainted     *taint;             /* Taint information from CmpLog    */
  struct skipdet_entry *skipdet_e;

};

```
1. 这里首先会初始化一些`queue_entry`的字段,其中`weight`权重设置为1, `perf_score`设置为100等等
2. 查看该entry的`depth`是否大于最大深度,如果大于就更新这个`max_depth`
3. 查看queue_top,若存在则更新插入的这个,否则`afl->queue`和`afl->queue_top`也被赋值为q
4. afl相关的一些字段自增,`queued_items,active_items, pending_not_fuzzed`
5. 扩充一个存放`queue_entry`地址的数组,这个数组被记录在`afl->queue_buf`,数组个数取决于`afl->queued_items`,然后将q记录在末尾,并将q->id记录为index


# pivot_inputs
在输出目录中创建输入测试用例的硬链接，选择好名字并相应地调整

# setup_stdio_file
为了被fuzz的数据建立output文件,如果没使用-f的话,创建`tmp_dir/.cur_input`文件,将其作为`fsrv.out_file`

# setup_testcase_shmem
建立共享映射,使用共享内存来进行输入来进行fuzz
```c
void setup_testcase_shmem(afl_state_t *afl) {

  afl->shm_fuzz = ck_alloc(sizeof(sharedmem_t));

  // we need to set the non-instrumented mode to not overwrite the SHM_ENV_VAR
  u8 *map = afl_shm_init(afl->shm_fuzz, MAX_FILE + sizeof(u32), 1);
  afl->shm_fuzz->shmemfuzz_mode = 1;

  if (!map) { FATAL("BUG: Zero return from afl_shm_init."); }

#ifdef USEMMAP
  setenv(SHM_FUZZ_ENV_VAR, afl->shm_fuzz->g_shm_file_path, 1);
#else
  u8 *shm_str = alloc_printf("%d", afl->shm_fuzz->shm_id);
  setenv(SHM_FUZZ_ENV_VAR, shm_str, 1);
  ck_free(shm_str);
#endif
  afl->fsrv.support_shmem_fuzz = 1;
  afl->fsrv.shmem_fuzz_len = (u32 *)map;
  afl->fsrv.shmem_fuzz = map + sizeof(u32);

}
```
这个函数是设置fsrv的一些共享内存相关字段


# afl_shm_init
这个函数用来配置共享内存, 返回`shm->map`,这里新创建的shmem会链接到全局的`shm_list`当中
```c
/* afl-sharedmem.c */
static list_t shm_list = {.element_prealloc_count = 0};
```

# afl_fsrv_start
启动fork服务器
这里构造了两个pipe`st_pipe, ctl_pipe`, 然后fork一个子进程作为`fork server`

## CHILD PROCESS

下面是child_process代码
```c
  if (!fsrv->fsrv_pid) {

    /* 子进程 */

    // enable terminating on sigpipe in the childs
    struct sigaction sa;
    memset((char *)&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigaction(SIGPIPE, &sa, NULL);

      /* 用于限制被fuzz程序消耗的资源 */
    struct rlimit r;

      /* 资源限制设置 */
    ....
    /* 隔离进程并配置标准描述符。如果指定了out_file，则stdin为/dev/null；否则，将克隆 out_fd
    Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    if (!(debug_child_output)) {

          /* 这里将任何对于stdout和stderr的输出都会重定位到dev_null设备中 */
      dup2(fsrv->dev_null_fd, 1);
      dup2(fsrv->dev_null_fd, 2);

    }
/* 如果不使用stdin */
    if (!fsrv->use_stdin) {
/* 任何从stdin输入将会从dev_null读入 */
      dup2(fsrv->dev_null_fd, 0);

    } else {

          /* 将服务器的输入改编为out_fd所指向的文件 */
      dup2(fsrv->out_fd, 0);
      close(fsrv->out_fd);

    }

      /* 设置控制和状态pipe, 关闭不需要的原始fd */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) { PFATAL("dup2() failed"); }
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) { PFATAL("dup2() failed"); }

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(fsrv->out_dir_fd);
    close(fsrv->dev_null_fd);
    close(fsrv->dev_urandom_fd);

    if (fsrv->plot_file != NULL) {

      fclose(fsrv->plot_file);
      fsrv->plot_file = NULL;

    }

      ...

    /* Set sane defaults for sanitizers */
      /* 通过服务器的环境变量来设置子进程自身的sanitizers */
    set_sanitizer_defaults();

    fsrv->init_child_func(fsrv, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32 *)fsrv->trace_bits = EXEC_FAIL_SIG;
    FATAL("Error: execv to target failed\n");

  }
```
这里子进程所作的事情如下
1. 对于自身资源的消耗做出了控制
2. 然后隔离了自身进程并修改了一些标准描述符,隔离进程并配置标准描述符。如果指定了out_file，则stdin为/dev/null；否则，将克隆 out_fd。
3. 然后设置自身的`control_pipe`和`status_pipe`, 其中只保留了`ctl_pipe`的读和`st_pipe`的写, 然后分别将其fd重定位到`FORKSRV_FD, FORKSRV_FD+1`
4. 关闭多余的fd并设置`sanitizer`
5. 执行二进制函数, 这里`fsrv->init_child_func`被指向为`fsrv_exec_child`,这里的赋值是由`afl_fsrv_init`函数来做的

## fsrv_exec_child
```c
static void fsrv_exec_child(afl_forkserver_t *fsrv, char **argv) {

  if (fsrv->qemu_mode || fsrv->cs_mode) {

    setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 0);

  }

  execv(fsrv->target_path, argv);

  WARNF("Execv failed in forkserver.");

}
```
这里是子进程执行`targer_path`路径所代表的程序,作为服务器来运行,值得注意的是经过调试这里的`target_path`就是我们被fuzz的程序,但是在运行之时他的功能为一个fuzz服务器,跟进调试发现他在运行`instrumentation/`目录下一个c程序的代码,应该是我们初步`afl-cc`的时候进行插桩导致的

## PARENT PROCESS
1. 首先打印子进程pid
2. 关闭多于的fd,这里只保留`ctl_pipe`的写和`st_pipe`的读
3. 等待fork服务器的启动,不会耗费太多时间
4. 尝试从`st_fd`读取四字节信息来获知服务器已经启动


# load_auto

加载自动生成的extras
这里的`extras`指的是确定性的注入词典术语,可以显示为`用户`或者`自动

# deunicode_extras
有时输入中的字符串会在内部转换为 unicode，因此对于模糊测试，如果它看起来像简单的 unicode，我们应该尝试去 解码unicode

# dedup_extras
从加载到的extras中移除复制部分, 这里能够在多个文件被加载时发生

# perform_dry_run
对所有测试用例执行试运行，以确认应用程序按预期工作。这仅针对初始输入执行，并且仅执行一次

1. for循环读取每个`queue_entry`
2. 打开`queue_entry`对应的文件
3. 将文件内容拷贝到`afl->use_mem`当中



# calibrate_case
校准新的测试用例。这是在处理输入目录以尽早警告不稳定或其他有问题的测试用例时完成的；当发现新路径来检测可变行为时等等

1. 如果校准的entry不是来自queue或者现在是恢复fuzz会话,那么超时时间将增加一部分,这样有助于避免间歇性延迟而产生的问题
2. 设置`afl->stage_name = "calibration";`, `q->cal_failed++`
3. 设置`afl->stage_max`, 通过环境变量是否有`afl_env.afl_cal_fast`来决定,这里的主要含义是每个测试用例测试的最大数量,`CAL_CYCLES_FAST=3, CAL_CYCLES=7`
3. 确保forkserver是开启状态
4. 检查`q->exec_cksum`,如果该值不为0则表示其不是来自input文件夹, 将`fsrv.trace_bits`复制到`afl->first_trace`当中,然后调用`has_new_bits`来检查是否有`virgin`位图改变
5. 获取当前时间,遍历`afl->stage_max`次来进行检测
    1. 调用`write_to_testcase`,将读取的测试内容写入`fsrv->shmem_fuzz`中
    2. 调用`fuzz_run_target`,这个函数实际上是`afl_fsrv_run_target`的wrapper
    3. 更新校验时间
    4. 调用`classify_counts`,将执行次数规整化(1->1, 2->2, 3->4, 4->4),都使用一个bytes来表示
    5. 计算`fsrv.trace_bits`的hash值,然后同exec_cksum进行比较, 如果不相同则更新`virgin_bits`
    6. 如果`exec_cksum`为0,说明该entry是input目录下构成的,则将`afl->exec_cksum = cksum`, 再将`trace_bits`拷贝到`afl->first_trace`中
    7. 如果`exec_cksum`不为0, 则说明他不是来自input目录,然后判断他是否是可变entry,从0到`map_size`开始遍历,如果发现当前字节`var_bytes[i]`为0, 且`first_trace[i] != trace_bits[i]`,则`将var_byts[i]`置1, 且`virgin_bits[i] = 0`用来表示标志他为完全发现,然后最后设置`var_detected = 1`用来表示检测到可变entry, 此时将`stage_max`增加一部分,最多12
6. 设置相关时间
7. 更新位图分数
7. 如果发现检测到可变路径,则标记该entry为可变性状


# has_new_bits
检查当前执行路径是否给表带来了任何新内容。更新原始位以反映发现。
+ 如果唯一的变化是特定元组的命中计数，则返回 1； 
+ 如果有新的元组出现则返回2。
+ 更新地图，因此后续调用将始终返回 0。
+ 该函数在相当大的缓冲区上的每次 exec() 之后调用，因此它需要很快。我们在 32 位和 64 位版本中执行此操作

这里有两个位图, 一个是`afl.fsrv->trace_bits`,还有一个是`afl->virgin_map`
1. 获取真实位图的字节大小
2. 每字节按位比较两个位图,调用`discover_word`,来发现是否有发现新路径,如果有则更新`virgin_map`
3. 如果传入的参数`virgin_map == afl->virgin_bits`则将`afl->bitmap_changed = 1`, 然后返回修改

注意`virgin_map`保存的是没有被覆盖的基本快,初始为全1

# write_to_testcase
主要是将之前测试用例的`use_mem`写入到`afl.fsrv->shmem_fuzz`当中

# count_bytes
计算给定的位图中有多少字节有置位

# update_bitmap_score
当我们遇到一条新路径时，我们称其为查看该路径是否比任何现有路径更有利。 “有利条件”的目的是拥有一组最小的路径来触发迄今为止在位图中看到的所有位，并专注于对它们进行模糊测试，而牺牲其余部分。
   该过程的第一步是维护位图中每个字节的`afl->top_erated[]`  条目列表。如果没有先前的竞争者，或者竞争者具有更有利的速度 x 尺寸系数，我们将赢得该位置

进行for循环判断位图每个字节
1. 判断调度器类型
2. 使用`q->exec_us * q->len`来作为评价标准
3. 如果`trace_bits[i]`不为0,则说明该路径已经被覆盖到, 进行下一步
4. 然后判断对应该path的`top_rated[i]`是否存在,如果存在,则同样计算`top_rated[i]`的评价标准,然后与`trace_bits[i]`的评价标准作比较,如果发现并没有优化,则进行下一字节的判断,返回步骤1,否则继续
5. 将`top_rated[i]->tc_ref--`,如果这个计数为0, 则释放掉`top_rated[i]->trace_mini`
6. 到这里说明`trace_bit[i]`更优, 则将`top_rated[i] = q`,然后增加q的计数,如果`q->trace_mini`为空,则重新分配字节, 然后将`q->trace_bits`压缩存储到其中,也就是说原本的可以标注path执行次数的`trace_bits`变作只记录是否访问到的`trace_mini`
7. 将`afl->score_changed = 1`



# discover_word
```c
inline void discover_word(u8 *ret, u64 *current, u64 *virgin) {

    /* 检查current和virgin都非空 */
  if (*current & *virgin) {

        /* 初始调用时ret为0, 根据上一次的discover来判断 */
    if (likely(*ret < 2)) {

      u8 *cur = (u8 *)current;
      u8 *vir = (u8 *)virgin;

      /* Looks like we have not found any new bytes yet; see if any non-zero
         bytes in current[] are pristine in virgin[]. */
            /* 这里注意==的优先级高于&&,意思为如果cur[0]不为全0并且vir[0]是初始化状态 */

      if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
          (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
          (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
          (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
        *ret = 2;
      else
        *ret = 1;

    }

    *virgin &= ~*current;

  }

}
```

整个函数的目的是寻找是否存在在`virgin_map`为初始化的某个比特位,`current_map`有了新的发现,如果有则更新`virgin_map`

# afl_fsrv_run_target
执行目标进程,检测是否超时, 返回状态信息,他是`afl_fsrv_run_target`的一层wrapper
1. 如果不是`nyx_mode`,则设置`fsrv->trace_bits`为0
2. 向`fsrv_ctl_fd`写入控制字段,告诉`fork server`上次运行是否超时
3. 设置`fsrv->last_run_timed_out = 0` 
4. 从`fsrv_st_fd`读取fork子进程的pid
5. 在一定的超时范围内读取fork子进程的状态
6. 如果发现超时,则杀掉fork子进程,然后设置上次超时标志位
7. `fsrv->total_execs++`,这个标志位是记录了`run_target`被使用了多少次
8. 然后这里存在一个内存屏障用来保存对于`fsrv->trace_bits`的操作都在这之下
9. 进行一些相关的检查,例如是否执行失败,是否运行超时
10. 查看是否crash, 处理crash
11. 否则返回执行正确

# cull_queue

该函数遍历 `afl->top_erated[]` 条目
这个条目是当前字节所在的路径下,执行最优的`queue_entry`,即最短时间*最短长度达到此路径
然后顺序抓取以前未见过的字节 (temp_v) 的获胜者，并将它们标记为受欢迎的，至少直到下一次运行。
在所有模糊测试步骤中，受欢迎的条目会获得更多的执行步骤


```c
void cull_queue(afl_state_t *afl) {

    /* 如果afl发现score未改变或者说是非插桩模式,则直接返回 */
  if (likely(!afl->score_changed || afl->non_instrumented_mode)) { return; }

    /* map_size右移三位也就是➗8获取字节 */
  u32 len = (afl->fsrv.map_size >> 3);
  u32 i;
    /* 获取afl的map_tmp_buf, 这是大小为map_size的固定缓冲区,任何函数都可以使用 */
  u8 *temp_v = afl->map_tmp_buf;

    /* 分数改变清空 */
  afl->score_changed = 0;

   /* 清空temp_v数组 */
  memset(temp_v, 255, len);

  afl->queued_favored = 0;
  afl->pending_favored = 0;

    /* 初始化 */ for (i = 0; i < afl->queued_items; i++) {
    afl->queue_buf[i]->favored = 0;

  }
....
```
上面的部分对队列进行了一系列标识符的初始化

```c
  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a afl->top_rated[] contender, let's use it. */

  afl->smallest_favored = -1;

  /* 按照bit位来遍历 */
  for (i = 0; i < afl->fsrv.map_size; ++i) {

      /* 这里的top_entries是bitmap bytes中的排名较高的entries */
      /* trace_mini 是追踪字节 */
      /* 这里if通过的条件是该此时的top_rated指向的queue_entry是否覆盖当前路径 */
      /* 这里进入if的条件是该top_entry[i]存在， temp_v[i]并没有被之前的路径覆盖， 且当前的top_entry[i]覆盖了位图i所在的路径 */
    if (afl->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7))) &&
        afl->top_rated[i]->trace_mini) {

      u32 j = len;

      /* Remove all bits belonging to the current entry from temp_v. */
          /* 从temp_v中移除隶属于当前entry能覆盖的所有的比特位 */

      while (j--) {

        if (afl->top_rated[i]->trace_mini[j]) {

                  /* temp_v[j]赋值为0表示这条路径覆盖到了 */
          temp_v[j] &= ~afl->top_rated[i]->trace_mini[j];

        }

      }
          /* 如果当前路径每标记为受青睐 */

      if (!afl->top_rated[i]->favored) {

              /* 设置favored位 */
        afl->top_rated[i]->favored = 1;
        ++afl->queued_favored;

              /* 如果当前entry没有被fuzz过 */
        if (!afl->top_rated[i]->was_fuzzed) {

          ++afl->pending_favored;
          if (unlikely(afl->smallest_favored < 0)) {

            afl->smallest_favored = (s64)afl->top_rated[i]->id;

          }

        }

      }

    }

  }
```
这里的迭代实际上就是寻找能覆盖当前路径的`queue_entry`集合,且这里的集合还是最优的,集合内的`entry`标记为`favored`

# show_init_stats
快速的显示统计信息

# write_stats_file
如果当前是插桩模式的话则调用这个函数
无监督的监控stats文件

# ---- fuzzer正式开启 ----
这里存在一个while循环用来控制整体的fuzzer进程
1. 调用`cull_queue`函数来处理fuzz队列
2. 如果`pending_favored && smallest_favored >= 0`,则将`afl->current_entry`设置为`smallest_favored`, 这里的`smallest_favored`一般为-1或着指向`top_rated[]->id`,然后将设置`afl->queue_cur`
3. 执行`fuzz_one`

# fuzz_one
这里是变异的入口点,寻找默认变异器,优化等级取决于配置 
```c
  /*
     -L command line paramter => limit_time_sig value
       limit_time_sig == 0 then run the default mutator
       limit_time_sig  > 0 then run MOpt
       limit_time_sig  < 0 both are run
  */

  if (afl->limit_time_sig <= 0) { key_val_lv_1 = fuzz_one_original(afl); }
  ...
```
如果`-L`参数没有特殊置位,那么将会调用`fuzz_one_original`

# fuzz_one_original
从队列中取出当前entry, 然后对其进行模糊测试, 这里的返回值为0表示成功fuzz,如果返回1则表示跳过

如果有待受青睐的entry,也就是`afl->pending_favored`,
```c

  if (likely(afl->pending_favored)) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */
      /* 如果我们有受到青睐并且没有被fuzz过的新路径到达， 或许我们将会跳过fuzz,但会牺牲掉已经被fuzz或者不受青睐的例子 */

    if ((afl->queue_cur->fuzz_level || !afl->queue_cur->favored) &&
          /* 99%概率跳过 */
        likely(rand_below(afl, 100) < SKIP_TO_NEW_PROB)) {

      return 1;

    }
  } else if (!afl->non_instrumented_mode && !afl->queue_cur->favored &&

             afl->queued_items > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */
      /* 否则，仍然大概率跳过不受青睐的例子， 尽管较少
       * 跳过的概率高于已经被fuzz的输入，低于从没被fuzz过的entry */

    if (afl->queue_cycle > 1 && !afl->queue_cur->fuzz_level) {
          /* 75%的概率跳过 */
      if (likely(rand_below(afl, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

    } else {
          /* 95%的概率跳过 */
      if (likely(rand_below(afl, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }

    }

  }
```
这里的函数首先判断fuzz队列里面有没有待青睐的entry,
如果有则将会执行如下几个if判断条件
1. 如果说当前`afl->queue_cur`如果没有被标记为青睐或者已经被fuzz过了，则有99%的概率跳过此轮
如果没有待青睐的entry,则判断当前`afl->queue_cur`如果未受到青睐，且队列条目大于10,则仍然大概率跳过此轮fuzz

经过上面的判断，这里存在的大部分是受到青睐的`queue_entry`,并且一般是没有被fuzz过的

```c
/* 从当前的queue entry中获得测试样例文件的buffer */
  orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);
  len = afl->queue_cur->len;

/* 重新分配输出buffer */
  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;
```
接下来就是fuzz的几个阶段

# CALIBRATION 阶段
该阶段用来校验测试用例


```c
  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (unlikely(afl->queue_cur->cal_failed)) {

    u8 res = FSRV_RUN_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {

      afl->queue_cur->exec_cksum = 0;

      res =
          calibrate_case(afl, afl->queue_cur, in_buf, afl->queue_cycle - 1, 0);

      if (unlikely(res == FSRV_RUN_ERROR)) {

        FATAL("Unable to execute target application");

      }

    }

    if (unlikely(afl->stop_soon) || res != afl->crash_mode) {

      ++afl->cur_skipped_items;
      goto abandon_entry;

    }

  }
```
# TRIMMING阶段


# FAST(exponential)
指数
# COE(cut-off exponential)
截止指数
# LIN(linear)
线性
# QUAD(quadratic)
二次
# MMOPT(modified M0pt)
修改后的M0pt优化
# RARE(rare edge focus)
罕见的边缘焦点
# SEEK(seek)
寻找
# EXPLORE(exploration-based constant)
基于探索的常数






