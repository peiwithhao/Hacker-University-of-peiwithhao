#include <asm/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

static int nl_fd = 0; 
#define bool int
#define True 1
#define False 0
#define ulog(f, a...) fprintf(stdout, f, ##a)

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

    ulog("subscribing to %u.%u", CN_IDX_PROC, CN_VAL_PROC);
    /* 将该sock绑定到指定组 */
    if(bind(sock_fd, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1){
        perror("bind");
        close(nl_fd);
        return -1;
    }
    return sock_fd;
}

static int listen_to_events(int nl_sock_fd, bool enable){
    /*  */
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;




}

int main(void){
    /* 绑定到cn_proc驱动 */
    nl_fd = link_start();
    if(nl_fd == -1){
        exit(1);
    }




    close(nl_fd);
    return 0;
}



