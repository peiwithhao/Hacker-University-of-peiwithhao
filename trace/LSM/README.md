# LSM Hook Point
不知道这里说什么,就说一下最近一个"指导老师"(大嘘)让我写的LSM_hook点
这里只是我的小声抱怨,以后在进行学习的时候调整过来(主要是最近被它压榨的很烦)


| LSMhook点             | 内容                                      |
| --------------------- | ----------------------------------------- |
| sb_umount             | 卸载文件系统                              |
| sb_mount              | 挂载文件系统                              |
| sb_remount            | 修改文件系统挂载选项                      |
| sb_statfs             | task尝试获取文件系统统计信息              |
|                       |                                           |
| file_permission       | 每次文件读取和写入操作时重新验证读写权限  |
| file_alloc_security   | 在file->f_security分配一个安全结构体      |
| file_free_security    | 在file->f_security释放一个安全结构体      |
| file_locks            | 使用锁同步多个读取或写入访问文件时        |
| file_ioctl            | 处理ioctl系统调用发起的操作               |
| file_fcntl            | 处理fcntl系统调用发起的操作               |
| file_mprotect         | 改变内存权限之前触发                      |
| file_set_fowner       | 设置持有者的安全信息                      |
| file_open             | 打开文件                                  |
|                       |                                           |
| inode_create          | 创建普通文件                              |
| inode_mkdir           | 创建新目录或者已经存在的目录              |
| inode_rmdir           | 移除目录                                  |
| inode_mknod           | 通过mknod来创建特殊文件(例如socket或fifo) |
| inode_rename          | 修改文件或文件夹名称                      |
|                       |                                           |
| inode_link            | 给一个文件创建新的硬连接                  |
| inode_unlink          | 移除一个文件的硬连接                      |
| inode_symlink         | 创建一个文件的符号链接                    |
| inode_readlink        | 读一个文件的符号链接                      |
| inode_follow_link     | 从一个符号链接寻找路径名的时刻            |
|                       |                                           |
| inode_getattr         | 获得文件属性                              |
| inode_setattr         | 设置文件属性                              |
| inode_getxattr        | 获取文件扩展属性                          |
| inode_setxattr        | 设置文件扩展属性                          |
| inode_permissions     | 访问一个inode时                           |
|                       |                                           |
| bprm_creds_for_exec   | 在准备执行新程序之前设置cred              |
| bprm_creds_from_file  | 在文件中读取程序的cred时调用              |
| bprm_check_security   | 在执行程序之前进行安全检查                |
| bprm_committing_creds | 确认要执行程序并提交cred时调用            |
| bprm_commited_creds   | 在cred提交后调用                          |


> !注意,bprm部分是GPT提供的解释,这里作为参考



