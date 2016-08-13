#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "DataTypes.h"
#include "Utils.h"

static struct mf_rule policy_list;

/*
 * the hook function itself: regsitered for filtering outgoing packets
 */
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff* skb,
                           const struct net_device* in, const struct net_device* out,
                           int (*okfn)(struct sk_buff*))
{

	// get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol
	struct iphdr* ip_header = (struct iphdr*)skb_network_header(skb);
	struct udphdr* udp_header;
	struct tcphdr* tcp_header;
	struct list_head* p;
	struct mf_rule* a_rule;
	int i = 0;

	// get src and dest ip addresses
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;

	// get src and dest port number
	if (ip_header->protocol==17)
	{
		udp_header = (struct udphdr*)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(udp_header->source);
		dest_port = (unsigned int)ntohs(udp_header->dest);
	}
	else
	{
		if (ip_header->protocol == 6)
		{
			tcp_header = (struct tcphdr*)skb_transport_header(skb);
			src_port = (unsigned int)ntohs(tcp_header->source);
			dest_port = (unsigned int)ntohs(tcp_header->dest);
		}
	}

	printk(KERN_INFO "OUT packet info:"
	       "src ip: %u,"
	       "src port: %u,"
	       "dest ip: %u,"
	       "dest port: %u"
	       "proto: %u"
	       , src_ip
	       , src_port
	       , dest_ip
	       , dest_port
	       , ip_header->protocol
	      );

	// go through the firewall list and check if there is a match
	// in case there are multiple matches, take the first one
	list_for_each(p, &policy_list.list)
	{
		i++;
		a_rule = list_entry(p, struct mf_rule, list);
		printk(KERN_INFO "rule %d:"
		       "a_rule->in_out = %u,"
		       "a_rule->src_ip = %u,"
		       "a_rule->src_netmask=%u,"
		       "a_rule->src_port=%u,"
		       "a_rule->dest_ip=%u,"
		       "a_rule->dest_netmask=%u,"
		       "a_rule->dest_port=%u,"
		       "a_rule->proto=%u,"
		       "a_rule->action=%u"
		       ,i
		       , a_rule->in_out
		       , a_rule->src_ip
		       , a_rule->src_netmask
		       , a_rule->src_port
		       , a_rule->dest_ip
		       ,a_rule->dest_netmask
		       , a_rule->dest_port
		       , a_rule->proto
		       , a_rule->action
		      );

		//if a rule doesn't specify as "out", skip it
		if (a_rule->in_out != 2)
		{
			printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out",
			       i, a_rule->in_out);
			continue;
		}
		else
		{
			//check the protocol
			if ((a_rule->proto==1) && (ip_header->protocol != 6))
			{
				printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP", i);
				continue;
			}
			else
			{
				if ((a_rule->proto==2) && (ip_header->protocol != 17))
				{
					printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP", i);
					continue;
				}
			}

			//check the ip address
			if (a_rule->src_ip==0)
			{
				//rule doesn't specify ip: match
			}
			else
			{
				if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask))
				{
					printk(KERN_INFO "rule %d not match: src ip mismatch", i);
					continue;
				}
			}

			if (a_rule->dest_ip == 0)
			{
				//rule doesn't specify ip: match
			}
			else
			{
				if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask))
				{
					printk(KERN_INFO "rule %d not match: dest ip mismatch", i);
					continue;
				}
			}

			//check the port number
			if (a_rule->src_port==0)
			{
				//rule doesn't specify src port: match
			}
			else
				if (src_port!=a_rule->src_port)
				{
					printk(KERN_INFO "rule %d not match: src port dismatch", i);
					continue;
				}

			if (a_rule->dest_port == 0)
			{
				//rule doens't specify dest port: match
			}
			else
			{
				if (dest_port!=a_rule->dest_port)
				{
					printk(KERN_INFO "rule %d not match: dest port mismatch", i);
					continue;
				}
			}

			//a match is found: take action
			if (a_rule->action==0)
			{
				printk(KERN_INFO "a match is found: %d, drop the packet", i);
				printk(KERN_INFO "---------------------------------------");
				return NF_ACCEPT; //NF_DROP;
			}
			else
			{
				printk(KERN_INFO "a match is found: %d, accept the packet", i);
				printk(KERN_INFO "---------------------------------------");
				return NF_ACCEPT;
			}
		}
	}
	printk(KERN_INFO "no matching is found, accept the packet");
	printk(KERN_INFO "---------------------------------------");
	return NF_ACCEPT;
}

/*
 * the hook function itself: registered for filtering incoming packets
 */
unsigned int hook_func_in(unsigned int hooknum
                          , struct sk_buff* skb
                          , const struct net_device* in
                          , const struct net_device* out
                          , int (*okfn)(struct sk_buff*)
                         )
{
	// get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol
	struct iphdr* ip_header = (struct iphdr*)skb_network_header(skb);
	struct udphdr* udp_header;
	struct tcphdr* tcp_header;
	struct list_head* p;
	struct mf_rule* a_rule;
	int i = 0;

	// get src and dest ip addresses
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;

	// get src and dest port number
	if (ip_header->protocol==17)
	{
		udp_header = (struct udphdr*)(skb_transport_header(skb)+20);
		src_port = (unsigned int)ntohs(udp_header->source);
		dest_port = (unsigned int)ntohs(udp_header->dest);
	}
	else
	{
		if (ip_header->protocol == 6)
		{
			tcp_header = (struct tcphdr*)(skb_transport_header(skb)+20);
			src_port = (unsigned int)ntohs(tcp_header->source);
			dest_port = (unsigned int)ntohs(tcp_header->dest);
		}
	}

	printk(KERN_INFO "IN packet info:"
	       "src ip: %u,"
	       "src port: %u,"
	       "dest ip: %u,"
	       "dest port: %u,"
	       "proto: %u"
	       , src_ip
	       , src_port
	       , dest_ip
	       , dest_port
	       , ip_header->protocol);

	//go through the firewall list and check if there is a match
	//in case there are multiple matches, take the first one
	list_for_each(p, &policy_list.list)
	{
		i++;
		a_rule = list_entry(p, struct mf_rule, list);
		printk(KERN_INFO "rule %d:"
		       "a_rule->in_out = %u,"
		       "a_rule->src_ip = %u,"
		       "a_rule->src_netmask=%u,"
		       "a_rule->src_port=%u,"
		       "a_rule->dest_ip=%u,"
		       "a_rule->dest_netmask=%u,"
		       "a_rule->dest_port=%u,"
		       "a_rule->proto=%u,"
		       "a_rule->action=%u"
		       ,i
		       , a_rule->in_out
		       , a_rule->src_ip
		       , a_rule->src_netmask
		       , a_rule->src_port
		       , a_rule->dest_ip
		       , a_rule->dest_netmask
		       , a_rule->dest_port
		       , a_rule->proto
		       , a_rule->action
		      );

		//if a rule doesn't specify as "i", skip it
		if (a_rule->in_out != 1)
		{
			printk(KERN_INFO "rule %d (a_rule->in_out:%u) not match: in packet, rule doesn't specify as in", i,
			       a_rule->in_out);
			continue;
		}
		else
		{
			//check the protocol
			if ((a_rule->proto==1) && (ip_header->protocol != 6))
			{
				printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP", i);
				continue;
			}
			else
			{
				if ((a_rule->proto==2) && (ip_header->protocol != 17))
				{
					printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP", i);
					continue;
				}
			}

			//check the ip address
			if (a_rule->src_ip==0)
			{
				//
			}
			else
			{
				if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask))
				{
					printk(KERN_INFO "rule %d not match: src ip mismatch", i);
					continue;
				}
			}

			if (a_rule->dest_ip == 0)
			{
				//
			}
			else
			{
				if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask))
				{
					printk(KERN_INFO "rule %d not match: dest ip mismatch", i);
					continue;
				}
			}

			//check the port number
			if (a_rule->src_port==0)
			{
				//rule doesn't specify src port: match
			}
			else
			{
				if (src_port!=a_rule->src_port)
				{
					printk(KERN_INFO "rule %d not match: src port mismatch", i);
					continue;
				}
			}

			if (a_rule->dest_port == 0)
			{
				//rule doens't specify dest port: match
			}
			else
			{
				if (dest_port!=a_rule->dest_port)
				{
					printk(KERN_INFO "rule %d not match: dest port mismatch", i);
					continue;
				}
			}

			//a match is found: take action
			if (a_rule->action==0)
			{
				printk(KERN_INFO "a match is found: %d, drop the packet", i);
				printk(KERN_INFO "---------------------------------------");
				return NF_ACCEPT; //NF_DROP;
			}
			else
			{
				printk(KERN_INFO "a match is found: %d, accept the packet", i);
				printk(KERN_INFO "---------------------------------------");
				return NF_ACCEPT;
			}
		}
	}
	printk(KERN_INFO "no matching is found, accept the packet");
	printk(KERN_INFO "---------------------------------------");
	return NF_ACCEPT;
}

void add_a_rule(struct mf_rule_desp* a_rule_desp)
{
	struct mf_rule* a_rule;
	a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);

	if (a_rule == NULL)
	{
		printk(KERN_INFO "error: cannot allocate memory for add_a_rule");
		return;
	}

	a_rule->in_out = a_rule_desp->in_out;
	a_rule->src_ip = ip_str_to_hl(a_rule_desp->src_ip);
	a_rule->src_netmask = ip_str_to_hl(a_rule_desp->src_netmask);
	a_rule->src_port = port_str_to_int(a_rule_desp->src_port);
	a_rule->dest_ip = ip_str_to_hl(a_rule_desp->dest_ip);
	a_rule->dest_netmask = ip_str_to_hl(a_rule_desp->dest_netmask);
	a_rule->dest_port = port_str_to_int(a_rule_desp->dest_port);
	a_rule->proto = a_rule_desp->proto;
	a_rule->action = a_rule_desp->action;

	printk(KERN_INFO "add_a_rule: "
	       "in_out=%u, "
	       "src_ip=%u, "
	       "src_netmask=%u, "
	       "src_port=%u, "
	       "dest_ip=%u, "
	       "dest_netmask=%u, "
	       "dest_port=%u, "
	       "proto=%u, "
	       "action=%u, "
	       , a_rule->in_out
	       , a_rule->src_ip
	       , a_rule->src_netmask
	       , a_rule->src_port
	       , a_rule->dest_ip
	       , a_rule->dest_netmask
	       , a_rule->dest_port
	       , a_rule->proto
	       , a_rule->action
	      );

	INIT_LIST_HEAD(&(a_rule->list));
	list_add_tail(&(a_rule->list), &(policy_list.list));
}

void add_a_test_rule(void)
{
	struct mf_rule_desp a_test_rule;
	printk(KERN_INFO "add_a_test_rule");
	printk(KERN_INFO "for IP 192.168.0.250");


	a_test_rule.in_out = 2;
	a_test_rule.src_ip = (char*)kmalloc(16, GFP_KERNEL);
	strcpy(a_test_rule.src_ip, "192.168.0.250");

	a_test_rule.src_netmask = (char*)kmalloc(16, GFP_KERNEL);
	strcpy(a_test_rule.src_netmask, "255.255.255.0");
	a_test_rule.src_port = NULL;
	a_test_rule.dest_ip = NULL;
	a_test_rule.dest_netmask = NULL;
	a_test_rule.dest_port = NULL;
	a_test_rule.proto = 6;
	a_test_rule.action = 0;

	add_a_rule(&a_test_rule);


	printk(KERN_INFO "for IP 192.168.0.103");

	a_test_rule.in_out = 2;
	a_test_rule.src_ip = (char*)kmalloc(16, GFP_KERNEL);
	strcpy(a_test_rule.src_ip, "192.168.0.103");
	a_test_rule.src_netmask = (char*)kmalloc(16, GFP_KERNEL);
	strcpy(a_test_rule.src_netmask, "255.255.255.0");
	a_test_rule.src_port = NULL;
	a_test_rule.dest_ip = NULL;
	a_test_rule.dest_netmask = NULL;
	a_test_rule.dest_port = NULL;
	a_test_rule.proto = 6;
	a_test_rule.action = 0;

	add_a_rule(&a_test_rule);
}

void delete_a_rule(int num)
{
	int i = 0;
	struct list_head* p, *q;
	struct mf_rule* a_rule;
	printk(KERN_INFO "delete a rule: %d", num);
	list_for_each_safe(p, q, &policy_list.list)
	{
		++i;

		if (i == num)
		{
			a_rule = list_entry(p, struct mf_rule, list);
			list_del(p);
			kfree(a_rule);
			return;
		}
	}
}
