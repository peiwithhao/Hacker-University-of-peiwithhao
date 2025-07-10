#include <asm/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>

static int nl_fd = 0; 
#define bool int
#define True 1
#define False 0
#define ulog(f, a...) fprintf(stdout, f, ##a)
#define MAX_MSGSIZE 256


static int link_start(void){
    int sock_fd;
    struct sockaddr_nl l_local;

    sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (sock_fd == -1){
        perror("socket");
        return -1;
    }
    /* 配置sockaddr_nl */
    l_local.nl_family = AF_NETLINK;
    l_local.nl_groups = CN_IDX_PROC;
    l_local.nl_pid = getpid();

    ulog("subscribing to %u.%u\n", CN_IDX_PROC, CN_VAL_PROC);
    /* 将该sock绑定到指定组 */
    if(bind(sock_fd, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1){
        perror("bind");
        close(nl_fd);
        return -1;
    }
    return sock_fd;
}

/* mode:  */
static int switch_cn_proc_mode(int mode){
    struct nlmsghdr *nlhdr = NULL;
    struct msghdr msg;
    struct cn_msg * cnmsg;
    int * connector_mode;
    struct iovec iov;
    struct sockaddr_nl daddr;
    int ret;

    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0;
    daddr.nl_groups = CN_IDX_PROC;

    /* 分配整个消息地址空间 */
    nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_MSGSIZE));
    memset(nlhdr, 0, NLMSG_SPACE(MAX_MSGSIZE));
    memset(&iov, 0, sizeof(struct iovec));
    memset(&msg, 0, sizeof(struct msghdr));
    /* cnmsg 位于nlhdr下面 */
    cnmsg = (struct cn_msg *)NLMSG_DATA(nlhdr);
    connector_mode = (int *)cnmsg->data;
    *connector_mode = mode;

    /* 构造nlhdr */
    /* 主要长度构成: nlmsghdr + cn_msg + proc_cn_mcast_op, 后面的部分用来控制连接器 */
    nlhdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
    nlhdr->nlmsg_pid = getpid();
    nlhdr->nlmsg_flags = 0;
    nlhdr->nlmsg_type = NLMSG_DONE;  //信息内容类型
    nlhdr->nlmsg_seq = 0;           //信息序列号

    /* 构造cn_msg */
    cnmsg->id.idx = CN_IDX_PROC;
    cnmsg->id.val = CN_VAL_PROC;
    cnmsg->seq = 0;
    cnmsg->ack = 0;
    cnmsg->len = sizeof(enum proc_cn_mcast_op);    //cn_msg的大小不包括头部

    /* 用iovec来组织信息 */
    iov.iov_base = (void *)nlhdr;
    iov.iov_len = nlhdr->nlmsg_len;
    msg.msg_name = (void *)&daddr;
    msg.msg_namelen = sizeof(daddr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ret = sendmsg(nl_fd, &msg, 0);
    if(ret == -1){
        perror("sendmsg");
        exit(-1);
    }
    free(nlhdr);
    return ret;
}


/* 信号处理 */
void sigint_handler(int signo){
    /* 关闭进程事件的报告 */
    switch_cn_proc_mode(PROC_CN_MCAST_IGNORE);
    printf("process event: turn off process event listening..\n");
    close(nl_fd);
    exit(0);
}

/* 接受消息并处理 */
void handle_cn_proc_msg(struct nlmsghdr *nlhdr){
    struct msghdr msg;
    int * connector_mode;
    struct iovec iov;
    struct sockaddr_nl daddr;
    struct cn_msg *cnmsg;
    struct proc_event * procevent;
    int ret;

    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0;
    daddr.nl_groups = CN_IDX_PROC;

    memset(nlhdr, 0, NLMSG_SPACE(MAX_MSGSIZE));
    memset(&iov, 0, sizeof(struct iovec));
    memset(&msg, 0, sizeof(struct msghdr));

    /* iov用于指定消息的存放位置以及最大可利用的缓存大小 */
    iov.iov_base = (void *)nlhdr;
    iov.iov_len = NLMSG_SPACE(MAX_MSGSIZE);

    /* msg_name表示希望接受的消息的目的地址 */
    msg.msg_name = (void *)&daddr;
    msg.msg_namelen = sizeof(daddr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ret = recvmsg(nl_fd, &msg, 0);
    if(ret == 0){
        printf("Exit\n");
        exit(0);
    }else if(ret == -1){
        perror("recvmsg");
        exit(1);
    }else{
        cnmsg = (struct cn_msg *)NLMSG_DATA(nlhdr);
        procevent = (struct proc_event *)cnmsg->data;
        switch(procevent->what){
            case PROC_EVENT_NONE:
                printf("process event: acknowledge for turning on process event listenning\n\n\n");
                break;
            case PROC_EVENT_FORK:
                printf("process event: fork\n");
                printf("parent tid:%d, pid:%d\nchild tid:%d, pid:%d\n\n\n",
                procevent->event_data.fork.parent_pid,
                procevent->event_data.fork.parent_tgid,
                procevent->event_data.fork.child_pid,
                procevent->event_data.fork.child_tgid);
                break;
            case PROC_EVENT_EXEC:
                printf("process event: exec\n");
                printf("tid:%d, pid:%d\n\n\n",
                procevent->event_data.exec.process_pid,
                procevent->event_data.exec.process_tgid);
                break;
            case PROC_EVENT_UID:
                printf("process event: uid\n");
                printf("process tid:%d, pid:%d, uid:%d->%d\n\n\n",
                procevent->event_data.id.process_pid,
                procevent->event_data.id.process_tgid,
                procevent->event_data.id.r.ruid,
                procevent->event_data.id.e.euid);
                break;
            case PROC_EVENT_GID:
                printf("process event: gid\n");
                printf("process tid:%d, pid:%d, uid:%d->%d\n\n\n",
                procevent->event_data.id.process_pid,
                procevent->event_data.id.process_tgid,
                procevent->event_data.id.r.rgid,
                procevent->event_data.id.e.egid);
                break;
            case PROC_EVENT_EXIT:
                printf("process event: exit\n");
                printf("tid:%d, pid:%d, exit code:%d\n\n\n",
                procevent->event_data.exit.process_pid,
                procevent->event_data.exit.process_tgid,
                procevent->event_data.exit.exit_code);
                break;
            default:
                printf("Unkown process action\n\n\n");
                break;
        }
    }
}

int main(void){
    /* 绑定到cn_proc驱动 */
    nl_fd = link_start();
    if(nl_fd == -1){
        exit(1);
    }

    /* 注册信号处理函数 */
    struct sigaction sigint_action;
    memset(&sigint_action, 0, sizeof(struct sigaction));
    sigint_action.sa_flags = SA_ONESHOT;
    sigint_action.sa_handler = &sigint_handler;
    sigaction(SIGINT, &sigint_action, NULL);

    /* 打开进程事件的报告 */
    switch_cn_proc_mode(PROC_CN_MCAST_LISTEN);
    printf("process event: turn on process event listening..\n");

    struct nlmsghdr *nlhdr = NULL;
    nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_MSGSIZE));
    while(1){
        handle_cn_proc_msg(nlhdr);
    }
    return 0;
}



