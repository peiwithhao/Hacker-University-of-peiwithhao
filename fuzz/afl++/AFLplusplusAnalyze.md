<!--toc:start-->
- [afl-cc](#afl-cc)
- [afl-fuzz](#afl-fuzz)
  - [setup_signal_handlers()](#setupsignalhandlers)
  - [check_asan_opts](#checkasanopts)
  - [fix_up_sync](#fixupsync)
  - [FAST(exponential)](#fastexponential)
  - [COE(cut-off exponential)](#coecut-off-exponential)
  - [LIN(linear)](#linlinear)
  - [QUAD(quadratic)](#quadquadratic)
  - [MMOPT(modified M0pt)](#mmoptmodified-m0pt)
  - [RARE(rare edge focus)](#rarerare-edge-focus)
  - [SEEK(seek)](#seekseek)
  - [EXPLORE(exploration-based constant)](#exploreexploration-based-constant)
<!--toc:end-->

# afl-cc
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

# afl-fuzz 

同样这里我们需要先简单看一下该afl-fuzz的c代码所涉及到的关键结构体`aflL`
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

  /*needed for afl_fuzz_one */
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
+ f:set target file, fsrv.out_file
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

## setup_signal_handlers()
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

## check_asan_opts
读取环境变量`ASAN_OPTIONS, MSAN_OPTIONS`,然后做相应检查
```c
void check_asan_opts(afl_state_t *afl) {

  u8 *x = get_afl_env("ASAN_OPTIONS");

  .....
  x = get_afl_env("MSAN_OPTIONS");
  ...
```

## fix_up_sync
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



## FAST(exponential)
## COE(cut-off exponential)
## LIN(linear)
## QUAD(quadratic)
## MMOPT(modified M0pt)
## RARE(rare edge focus)
## SEEK(seek)
## EXPLORE(exploration-based constant)





