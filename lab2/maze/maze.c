/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static int maze_dev_open(struct inode *i, struct file *f) {
	printk(KERN_INFO "maze: device opened.\n");
	return 0;
}

static int maze_dev_close(struct inode *i, struct file *f) {
	printk(KERN_INFO "maze: device closed.\n");
	return 0;
}

static ssize_t maze_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	printk(KERN_INFO "maze: read %zu bytes @ %llu.\n", len, *off);
	return len;
}

static ssize_t maze_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	printk(KERN_INFO "maze: write %zu bytes @ %llu.\n", len, *off);
	return len;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	printk(KERN_INFO "maze: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	return 0;
}

static const struct file_operations maze_dev_fops = {
	.owner = THIS_MODULE,
	.open = maze_dev_open,
	.read = maze_dev_read,
	.write = maze_dev_write,
	.unlocked_ioctl = maze_dev_ioctl,
	.release = maze_dev_close
};

static int maze_proc_read(struct seq_file *m, void *v) {
	char buf[] = "`hello, world!` in /proc.\n";
	seq_printf(m, buf);
	return 0;
}

static int maze_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, maze_proc_read, NULL);
}

static const struct proc_ops maze_proc_fops = {
	.proc_open = maze_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *maze_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init maze_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = maze_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
		goto release_class;
	cdev_init(&c_dev, &maze_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create("maze", 0, NULL, &maze_proc_fops);

	printk(KERN_INFO "maze: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit maze_cleanup(void)
{
	remove_proc_entry("maze", NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "maze: cleaned up.\n");
}

module_init(maze_init);
module_exit(maze_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
