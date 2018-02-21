#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include "../nf_faketcp.h"

enum {
	O_MODE = 0,
	F_MODE = 1 << O_MODE,
};

static void FAKETCP_help(void)
{
	printf(
"FAKETCP target options:\n"
" [--mode <int>]\n"
"	Modes to use:"
"   0. plain, just exchange IPPROTO_TCP(6) with IPPROTO_UDP(17).\n");
}

static const struct xt_option_entry FAKETCP_opts[] = {
	{.name = "mode", .id = O_MODE, .type = XTTYPE_UINT32},
	XTOPT_TABLEEND,
};


static void FAKETCP_parse(struct xt_option_call *cb)
{
	struct ipt_FAKETCP_info *info = cb->data;
	const struct ipt_entry *xt_entry = cb->xt_entry;

	if (!(xt_entry->ip.proto == IPPROTO_TCP
	    || xt_entry->ip.proto == IPPROTO_UDP)) {
			xtables_error(PARAMETER_PROBLEM,
						"FAKETCP: Need TCP or UDP protocol");
		}

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_MODE:
		info->mode = cb->val.u32;
		if (info->mode > IPT_FAKETCP_MAXMODE) {
			xtables_error(PARAMETER_PROBLEM,
						"FAKETCP: Mode cannot be greater than %d", IPT_FAKETCP_MAXMODE);
		}
		break;
	default:
		printf("Unknown argument\n");
	}
}

static void FAKETCP_fcheck(struct xt_fcheck_call *cb)
{
	struct ipt_FAKETCP_info *mr = cb->data;
}

static void FAKETCP_print(const void *ip, const struct xt_entry_target *target,
						int numeric)
{
	const struct ipt_FAKETCP_info *info = (const void *)target->data;

	printf(" mode %u", info->mode);
}

static void FAKETCP_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_FAKETCP_info *info = (const void *)target->data;

	printf(" --mode %u", info->mode);
}

static struct xtables_target faketcp_tg_reg = {
	.name		= "FAKETCP",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct ipt_FAKETCP_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_FAKETCP_info)),
	.help		= FAKETCP_help,
	.x6_parse	= FAKETCP_parse,
	.x6_fcheck	= FAKETCP_fcheck,
	.print		= FAKETCP_print,
	.save		= FAKETCP_save,
	.x6_options	= FAKETCP_opts,
};

void _init(void)
{
	xtables_register_target(&faketcp_tg_reg);
}
