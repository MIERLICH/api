// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * TODO 1/0: Fill in name / email
 * Author: 
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;


/* TODO 2: define your list! */
struct list_head head;
//static struct list_head *my_l;

struct my_list {
	char data[32];
	struct list_head list;
};

//LIST_HEAD(head);

static struct my_list *my_list_alloc(char *data, size_t len) {
	struct my_list *ti;
	
	ti = kmalloc(sizeof(struct my_list), GFP_KERNEL);
	if (ti == NULL)
		return NULL;
	memset(ti, 0, sizeof(struct my_list));
	memcpy(ti->data, data, len);
	return ti;
}

static void my_list_add_to_list(char *data, size_t len) {
	struct my_list *ti;
	ti = my_list_alloc(data, len);
	if (ti == NULL) {
		//printk("error alocare my_list_add_to_list\n");
		pr_info("error alocare my_list_add_to_list\n");
		return;
	}
	list_add(&ti->list, &head);
}

static void my_list_add_to_last_list(char *data, size_t len) {
	struct my_list *ti;
	ti = my_list_alloc(data, len);
	if (ti == NULL) {
		//printk("error alocare my_list_add_to_last_list\n");
		pr_info("error alocare my_list_add_to_last_list\n");
		return;
	}
	list_add_tail(&ti->list, &head);
}

static int list_proc_show(struct seq_file *m, void *v) {
	/* TODO 3: print your list. One element / line. */
	struct list_head *p, *q;
	struct my_list *ti;
	list_for_each_safe(p, q, &head) {
		ti = list_entry(p, struct my_list, list);
		//printk("%s\n", ti->data);
		pr_info("%s\n", ti->data);
		
	}
	return 0;
}

static void task_info_purge_list(void) {
	struct list_head *p, *q;
	struct my_list *ti;
	
	list_for_each_safe(p, q, &head) {
		ti = list_entry(p, struct my_list, list);
		list_del(p);
		kfree(ti);
	}
}

//printk("1) %d %ld\n", PROCFS_MAX_SIZE, local_buffer_size);
//printk("%d\n", len);
//printk("%s", ptr_to_name);
//printk("%s", ptr_to_name);
//printk("-[%c]-\n", *(ptr_to_name+3));
//printk("-[%c]-\n", *(ptr_to_name+4));

static int list_read_open(struct inode *inode, struct  file *file) {
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file) {
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;
	char *ptr_to_name = NULL;
	size_t len = 0;
	struct list_head *p, *q;
	struct my_list *ti;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains your command written in /proc/list/management
	 * TODO 4/0: parse the command and add/delete elements.
	 */
	 
	ptr_to_name = local_buffer + 5;
	len = strlen(ptr_to_name);
	*(ptr_to_name + len - 1) = '\0';
	if (!memcmp(local_buffer,"addf",4)) {
		//printk("addf operation\n");
		my_list_add_to_list(ptr_to_name, len);
	} else if (!memcmp(local_buffer,"adde",4)) {
		//printk("adde operation\n");
		my_list_add_to_last_list(ptr_to_name, len);
	} else if (!memcmp(local_buffer,"delf",4)) {
		//printk("delf operation\n");
		list_for_each_safe(p, q, &head) {
			ti = list_entry(p, struct my_list, list);
			if (!memcmp(ti->data,ptr_to_name,len-1)) {
				//printk("delete this : [%s]\n", ti->data);
				list_del(p);
				kfree(ti);
				break;
			}
		}
	} else if (!memcmp(local_buffer,"dela",4)) {
		//printk("delete all this: [%s]\n", ptr_to_name);
		list_for_each_safe(p, q, &head) {
			ti = list_entry(p, struct my_list, list);
			if (!memcmp(ti->data,ptr_to_name,len-1)) {
				//printk("1 ");
				list_del(p);
				kfree(ti);
			}
		}
	} else {
		//printk("Undefined comportament\n");
		pr_info("Undefined comportament\n");
		return -EFAULT;
	}

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	INIT_LIST_HEAD(&head);
	//LIST_HEAD(head);
	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void) {
	proc_remove(proc_list);
	task_info_purge_list();
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
/* TODO 5: Fill in your name / email address */
MODULE_AUTHOR("FirstName LastName <your@email.com>");
MODULE_LICENSE("GPL v2");
