/*
 * FakeTCP target (stateless) for IP tables
 * (C) 2018 by Xiaodong Qi <xdqi@outlook.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>
#include <net/checksum.h>
#include <linux/in.h>

#include <linux/netfilter/x_tables.h>
#include "../nf_faketcp.h"

MODULE_AUTHOR("Xiaodong Qi <xdqi@outlook.com>");
MODULE_DESCRIPTION("Xtables: Protocol field switching target (TCP & UDP only)");
MODULE_LICENSE("GPL");

static unsigned int
faketcp_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	const struct ipt_FAKETCP_info *info = par->targinfo;
	__u8 new_proto = 0;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	iph = ip_hdr(skb);

	switch (info->mode) {
	case IPT_FAKETCP_PLAIN:
		switch (iph->protocol) {
		case IPPROTO_TCP:
			new_proto = IPPROTO_UDP;
			break;
		case IPPROTO_UDP:
			new_proto = IPPROTO_TCP;
			break;
		default:
			break;
		}
	break;
	}

	if (new_proto && new_proto != iph->protocol) {
		// csum_replace2(&iph->check, iph->protocol << 8, new_proto << 8);
		iph->protocol = new_proto;
	}

	return XT_CONTINUE;
}

static unsigned int
faketcp_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ip6h;
	const struct ipt_FAKETCP_info *info = par->targinfo;
	__u8 new_proto = 0;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	ip6h = ipv6_hdr(skb);

	switch (info->mode) {
	case IPT_FAKETCP_PLAIN:
		switch (ip6h->nexthdr) {
		case IPPROTO_TCP:
			new_proto = IPPROTO_UDP;
			break;
		case IPPROTO_UDP:
			new_proto = IPPROTO_TCP;
			break;
		default:
			break;
		}
		break;
	}

	if (new_proto && new_proto != ip6h->nexthdr) {
		ip6h->nexthdr = new_proto;
	}

	return XT_CONTINUE;
}

static int faketcp_tg_check(const struct xt_tgchk_param *par)
{
	const struct ipt_FAKETCP_info *info = par->targinfo;

	if (info->mode > IPT_FAKETCP_MAXMODE) {
		pr_info("FAKETCP: invalid or unknown mode %u\n", info->mode);
		return -EINVAL;
	}
	return 0;
}

static int faketcp_tg6_check(const struct xt_tgchk_param *par)
{
	const struct ipt_FAKETCP_info *info = par->targinfo;

	if (info->mode > IPT_FAKETCP_MAXMODE) {
		pr_info("invalid or unknown mode %u\n", info->mode);
		return -EINVAL;
	}
	return 0;
}

static struct xt_target faketcp_tg_reg[] __read_mostly = {
	{
		.name       = "FAKETCP",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = faketcp_tg,
		.targetsize = sizeof(struct ipt_FAKETCP_info),
		.table      = "mangle",
		.checkentry = faketcp_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "FAKETCP",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = faketcp_tg6,
		.targetsize = sizeof(struct ipt_FAKETCP_info),
		.table      = "mangle",
		.checkentry = faketcp_tg6_check,
		.me         = THIS_MODULE,
	},
};

static int __init faketcp_tg_init(void)
{
	return xt_register_targets(faketcp_tg_reg, ARRAY_SIZE(faketcp_tg_reg));
}

static void __exit faketcp_tg_exit(void)
{
	xt_unregister_targets(faketcp_tg_reg, ARRAY_SIZE(faketcp_tg_reg));
}

module_init(faketcp_tg_init);
module_exit(faketcp_tg_exit);
MODULE_ALIAS("ipt_FAKETCP");
MODULE_ALIAS("ip6t_FAKETCP");
