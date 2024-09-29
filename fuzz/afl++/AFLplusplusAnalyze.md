<!--toc:start-->
- [afl-cc](#afl-cc)
<!--toc:end-->

# afl-cc
首先查看main函数的整体结构
```c
/* Main entry point */
int main(int argc, char **argv, char **envp) {

    //分配struct aflcc_state
  aflcc_state_t *aflcc = malloc(sizeof(aflcc_state_t));
    //根据传递参数初始化aflcc_state
  aflcc_state_init(aflcc, (u8 *)argv[0]);
    ...

}
```
这里简单解释一下,该代码是一层对于你给出的选项进行编译的wrapper, 实际上仍然是使用gcc或者是clang进行编译,所以涉及到编译的信息时再进行详细描述
我们平时采用的`afl-clang-fast`等编译指令,实际上都是对于该c代码所编译形成的elf的符号链接,而该elf则会根据你传递的第一个参数来进一步设置编译选项`argv[0]`

# afl-fuzz 

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

+ `a`:不区分大小写,设置`afl->input_mode`
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









