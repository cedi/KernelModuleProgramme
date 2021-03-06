#include <linux/module.h>
#include <linux/kernel.h>
#include "NfHooks.c"
#include "DataTypes.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NfHooks Firewall");
MODULE_AUTHOR("Cedric Kienzler");

//the structure used to register the function
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;

/*
 * For testing
 */
void add_a_test_rule(void)
{
	struct mf_rule_desp a_test_rule;
	printk(KERN_DEBUG "add_a_test_rule");
	printk(KERN_DEBUG "for IP 192.168.0.250");


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


	printk(KERN_DEBUG "for IP 192.168.0.103");

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

/*
 * Initialization routine
 */
int init_module()
{
	printk(KERN_INFO "load NfHooks Firewall");
	INIT_LIST_HEAD(&(policy_list.list));

	// Fill in the hook structure for incoming packet hook
	nfho.hook = hook_func_in;
	nfho.hooknum = NF_INET_LOCAL_IN;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);         // Register the hook

	// Fill in the hook structure for outgoing packet hook
	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);    // Register the hook

	// this part of code is for testing purpose
	add_a_test_rule();
	return 0;
}

/*
 * Cleanup routine
 */
void cleanup_module()
{
	struct list_head* p, *q;
	struct mf_rule* a_rule;
	nf_unregister_hook(&nfho);
	nf_unregister_hook(&nfho_out);
	printk(KERN_DEBUG "free policy list");

	list_for_each_safe(p, q, &policy_list.list)
	{
		printk(KERN_DEBUG "free one");
		a_rule = list_entry(p, struct mf_rule, list);
		list_del(p);
		kfree(a_rule);
	}

	printk(KERN_INFO "unload NfHooks Firewall");
}
