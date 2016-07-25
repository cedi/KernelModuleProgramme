
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define print_value(x) (x==NULL?"-" : x)

static struct mf_rule_struct
{
	int in_out;
	char* src_ip;
	char* src_netmask;
	char* src_port;            //default to -1
	char* dest_ip;
	char* dest_netmask;
	char* dest_port;
	char* proto;
	char* action;
} mf_rule;

static struct mf_delete_struct
{
	char* cmd;
	char* row;
} mf_delete;

void send_rule_to_proc()
{
	printf("TODO: send_rule_to_procn\n");
}

void send_delete_to_proc()
{
	printf("TODO: send_delete_to_procn\n");
}

void print_rule()
{
	printf("TODO: print_rulen\n");
	return;
}

int main(int argc, char** argv)
{
	int c;
	int action = 1;    //1: new rule; 2: print; 3: delete
	
	mf_rule.in_out = -1;
	mf_rule.src_ip = NULL;
	mf_rule.src_netmask = NULL;
	mf_rule.src_port = NULL;
	
	mf_rule.dest_ip = NULL;
	mf_rule.dest_netmask = NULL;
	mf_rule.dest_port = NULL;
	mf_rule.proto = NULL;
	mf_rule.action = NULL;
	
	while(1)
	{
		static struct option long_options[] =
		{
			/*set a flag*/
			{"in", no_argument, &mf_rule.in_out, 1},
			{"out", no_argument, &mf_rule.in_out, 0},
			/*These options don't set a flag.
			    We distinguish them by their indices.*/
			{"print", no_argument, 0, 'o'},
			{"delete", required_argument, 0, 'd'},
			{"srcip", required_argument, 0, 's'},
			{"srcnetmask", required_argument, 0, 'm'},
			{"srcport", required_argument, 0, 'p'},
			{"destip", required_argument, 0, 't'},
			{"destnetmask", required_argument, 0, 'n'},
			{"destport", required_argument, 0, 'q'},
			{"proto", required_argument, 0, 'c'},
			{"action", required_argument, 0, 'a'},
			{0, 0, 0, 0}
		};
		
		int option_index = 0;
		c = getopt_long(argc, argv, "od:s:m:p:t:n:q:c:a:", long_options, &option_index);
		
		/*Detect the end of the options. */
		if(c == -1)
		{
			break;
		}
		
		action = 1;
		
		switch(c)
		{
		case 0:
			printf("flag option: %s, mf_rule.in_out = %dn", long_options[option_index].name, mf_rule.in_out);
			break;
			
		case 'o':
			action = 2;    //print
			break;
			
		case 'd':
			action = 3;       //delete
			mf_delete.cmd = (char*)long_options[option_index].name;
			mf_delete.row = optarg;
			break;
			
		case 's':
			mf_rule.src_ip = optarg;  //src ip
			break;
			
		case 'm':
			mf_rule.src_netmask = optarg; //srcnetmask:
			break;
			
		case 'p':
			mf_rule.src_port = optarg;    //srcport:
			break;
			
		case 't':
			mf_rule.dest_ip = optarg;     //destip:
			break;
			
		case 'n':
			mf_rule.dest_netmask = optarg;    //destnetmask
			break;
			
		case 'q':
			mf_rule.dest_port = optarg;    //destport
			break;
			
		case 'c':
			mf_rule.proto = optarg; //proto
			break;
			
		case 'a':
			mf_rule.action = optarg;//action
			break;
			
		case '?':
			/* getopt_long printed an error message. */
			break;
			
		default:
			abort();
		}
		
		if(c != 0)
		{
			printf("%s = %sn",  long_options[option_index].name, optarg);
		}
	}
	
	if(action == 1)
	{
		send_rule_to_proc();
	}
	else if(action == 2)
	{
		print_rule();
	}
	else if(action == 3)
	{
		send_delete_to_proc();
	}
	
	if(optind < argc)
	{
		printf("non-option ARGV-elements: ");
		
		while(optind < argc)
		{
			printf("%s ", argv[optind++]);
		}
		
		putchar('n');
	}
}


