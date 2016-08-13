#ifndef _DATATYPES_H
#define _DATATYPES_H

/*
 * structure for firewall policies
 */
struct mf_rule_desp
{
	unsigned char in_out;
	char* src_ip;
	char* src_netmask;
	char* src_port;
	char* dest_ip;
	char* dest_netmask;
	char* dest_port;
	unsigned char proto;
	unsigned char action;
};

/*
 * structure for firewall policies
 */
struct mf_rule
{
	unsigned char in_out;		// 0: neither in nor out, 1: in, 2: out
	unsigned int src_ip;		//
	unsigned int src_netmask;	//
	unsigned int src_port;		// 0~2^32
	unsigned int dest_ip;		//
	unsigned int dest_netmask;	//
	unsigned int dest_port;		//
	unsigned char proto;		// 0: all, 1: tcp, 2: udp
	unsigned char action;		// 0: for block, 1: for unblock
	struct list_head list;
};

#endif // _DATATYÜES_H
