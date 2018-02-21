#ifndef _NETFILTER_NF_FAKETCP_H
#define _NETFILTER_NF_FAKETCP_H

#include <linux/netfilter.h>
#include <linux/if.h>

enum {
    IPT_FAKETCP_PLAIN = 0,
};

#define IPT_FAKETCP_MAXMODE IPT_FAKETCP_PLAIN

struct ipt_FAKETCP_info {
    __u32 mode;
};

#endif /* _NETFILTER_NF_FAKETCP_H */
