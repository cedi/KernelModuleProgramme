#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MeAmlloc");
MODULE_AUTHOR("Cedric Kienzler");

struct Person
{
	char name[30];
	unsigned int weight;
	unsigned char gender;
	struct list_head list; /* kernel's list structure */
};

struct Person personList;

int init_module()
{
	struct Person* aNewPerson;
	struct Person* aPerson;

	printk(KERN_INFO "initialize kernel module: MeAmlloc");
	INIT_LIST_HEAD(&personList.list);

	printk(KERN_INFO "allocate memory using kmalloc with GFP_KERNEL for first node");
	aNewPerson = kmalloc(sizeof(*aNewPerson), GFP_KERNEL);

	strcpy(aNewPerson->name, "GFP_KERNEL Cedric");
	aNewPerson->weight = 130;
	aNewPerson->gender = 1;

	INIT_LIST_HEAD(&aNewPerson->list);
	list_add_tail(&aNewPerson->list, &personList.list);

	printk(KERN_INFO "allocate memory using kmalloc with GFP_ATOMIC for 2nd node");
	aNewPerson = kmalloc(sizeof(*aNewPerson), GFP_ATOMIC);

	strcpy(aNewPerson->name, "GFP_ATOMIC Cedric");
	aNewPerson->weight = 130 * 2;
	aNewPerson->gender = 1;

	INIT_LIST_HEAD(&aNewPerson->list);
	list_add_tail(&aNewPerson->list, &personList.list);

	printk(KERN_INFO "allocate memory using vmalloc for 3rd node");
	aNewPerson = vmalloc(sizeof(*aNewPerson));

	strcpy(aNewPerson->name, "vmalloc Cedric");
	aNewPerson->weight = 130 * 3;
	aNewPerson->gender = 1;

	INIT_LIST_HEAD(&aNewPerson->list);
	list_add_tail(&(aNewPerson->list), &(personList.list));

	printk(KERN_INFO "traversing the list using list_for_each_entry()n");
	list_for_each_entry(aPerson, &personList.list, list)
	{
		//access the member from aPerson

		printk(KERN_INFO "Person: %s; weight: %d; gender: %sn", aPerson->name, aPerson->weight,
			   aPerson->gender == 0 ? "Female" : "Male");

	}

	return 0;
}
void cleanup_module()
{
	struct Person* aPerson;

	printk(KERN_INFO "kernel module unloaded: MeAmlloc");

	aPerson = list_first_entry(&personList.list, struct Person, list);
	printk(KERN_INFO "freeing node \"%s\"", aPerson->name);
	list_del(&aPerson->list);
	kfree(aPerson);

	aPerson = list_first_entry(&personList.list, struct Person, list);
	printk(KERN_INFO "freeing node \"%s\"", aPerson->name);
	list_del(&aPerson->list);
	kfree(aPerson);

	aPerson = list_first_entry(&personList.list, struct Person, list);
	printk(KERN_INFO "freeing node \"%s\"", aPerson->name);
	list_del(&aPerson->list);

	vfree(aPerson);
}
