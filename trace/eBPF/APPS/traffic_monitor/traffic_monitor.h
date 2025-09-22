#ifndef __TRAFFIC_MONITOR_H
#define __TRAFFIC_MONITOR_H

struct traffic_vqueue{
    unsigned long long lasttime;
    int credit;     /* bytes */
    unsigned int rate;  /* In byte per NS << 20 */
};

struct traffic_queue_stats {
    unsigned long rate;
    unsigned long stats:1, loopback:1;
    long long sum_credit;
};
#endif
