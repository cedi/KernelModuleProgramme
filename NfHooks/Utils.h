#include <linux/module.h>
#include <linux/kernel.h>

#ifndef _UTILS_H
#define _UTILS_H

unsigned int port_str_to_int(char* port_str)
{
	unsigned int port = 0;
	int i = 0;

	if (port_str==NULL)
	{
		return 0;
	}

	while (port_str[i] != (char)0)
	{
		port = port*10 + (port_str[i]-'0');
		++i;
	}

	return port;
}

/*
 * convert the string to byte array first
 * e.g.: from "131.132.162.25" to [131][132][162][25]
 */
unsigned int ip_str_to_hl(char* ip_str)
{
	unsigned char ip_array[4];
	int i = 0;
	unsigned int ip = 0;

	if (ip_str==NULL)
	{
		return 0;
	}

	memset(ip_array, 0, 4);

	while (ip_str[i]!='.')
	{
		ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i]!='.')
	{
		ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i]!='.')
	{
		ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i] != (char)0)
	{
		ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
	}

	/*convert from byte array to host long integer format*/
	ip = (ip_array[0] << 24);
	ip = (ip | (ip_array[1] << 16));
	ip = (ip | (ip_array[2] << 8));
	ip = (ip | ip_array[3]);

	//printk(KERN_DEBUG "ip_str_to_hl convert %s to %u", ip_str, ip);
	return ip;
}

/*
 * check the two input IP addresses, see if they match,
 * only the first few bits (masked bits) are compared
 */
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask)
{
	unsigned int tmp = ntohl(ip);    //network to host long
	int cmp_len = 32;
	int i = 0, j = 0;
	printk(KERN_DEBUG "compare ip: %u <=> %u", tmp, ip_rule);

	if (mask != 0)
	{
		//printk(KERN_DEBUG "deal with mask");
		//printk(KERN_DEBUG "mask: %d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]);
		cmp_len = 0;

		for (i = 0; i < 32; ++i)
		{
			if (mask & (1 << (32-1-i)))
			{
				cmp_len++;
			}

			else
			{
				break;
			}
		}
	}

	/*
	 * compare the two IP addresses for the first cmp_len bits
	 */
	for (i = 31, j = 0; j < cmp_len; --i, ++j)
	{
		if ((tmp & (1 << i)) != (ip_rule & (1 << i)))
		{
			printk(KERN_DEBUG "ip compare: %d bit doesn't match", (32-i));
			return false;
		}
	}

	return true;
}

#endif // _UTILS_H
