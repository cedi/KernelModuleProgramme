#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include<linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("person sample");
MODULE_AUTHOR("Cedric Kienzler");

struct Person
{
	char name[30];
	unsigned int weight;
	unsigned char gender;
	struct list_head list; /* kernel's list structure */
};

struct Person g_personList;

int init_module()
{
	struct Person* aNewPerson, *aPerson;
	unsigned int i;
	printk(KERN_INFO "initialize kernel modulen");
	INIT_LIST_HEAD(&g_personList.list);    //or LIST_HEAD(mylist);

	/* adding elements to mylist */
	for(i = 0; i < 5; ++i)
	{
		aNewPerson = kmalloc(sizeof(*aNewPerson), GFP_KERNEL);
		strcpy(aNewPerson->name, "Cedric");
		aNewPerson->weight = 130 * i;
		aNewPerson->gender = 1;
		INIT_LIST_HEAD(&aNewPerson->list);
		/* add the new node to mylist */
		list_add_tail(&(aNewPerson->list), &(g_personList.list));
	}

	printk(KERN_INFO "traversing the list using list_for_each_entry()n");
	list_for_each_entry(aPerson, &g_personList.list, list)
	{
		//access the member from aPerson
		printk(KERN_INFO "Person: %s; weight: %d; gender: %sn", aPerson->name, aPerson->weight,
			   aPerson->gender == 0 ? "Female" : "Male");
	}
	printk(KERN_INFO "n");
	return 0;
}

void cleanup_module()
{
	struct Person* aPerson, *tmp;
	printk(KERN_INFO "kernel module unloaded.n");
	printk(KERN_INFO "deleting the list using list_for_each_entry_safe()n");
	list_for_each_entry_safe(aPerson, tmp, &g_personList.list, list)
	{
		printk(KERN_INFO "freeing node %s", aPerson->name);
		list_del(&aPerson->list);
		kfree(aPerson);
	}
}
