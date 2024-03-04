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

#include "maze.h"			// for maze things

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static maze_t all_mazes[ 3];
static DEFINE_MUTEX(maze1_lock);
static DEFINE_MUTEX(maze2_lock);
static DEFINE_MUTEX(maze3_lock);

// internel kernel struct
typedef struct
{
	int host_process;
	coord_t player_pos;
} maze_attr;

static maze_attr all_maze_attr[ 3];


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
	
	// check each lock
	
	
	return len;
}

static void generate_maze( int location, coord_t dims)
{
	all_mazes[ location].w = dims.x;
	all_mazes[ location].h = dims.y;

	// temp values
	all_mazes[ location].ex = 2;
	all_mazes[ location].ey = 3;
	all_mazes[ location].sx = 3;
	all_mazes[ location].sy = 3;

	all_maze_attr[ location].player_pos = (coord_t){ all_mazes[ location].sx, all_mazes[ location].sy};

	// all_mazes[ 0].w = 11;
	// all_mazes[ 0].h = 7;
	for ( int i = 0; i < all_mazes[ 0].h; i += 1)
	{
		for ( int j = 0; j < all_mazes[ 0].w; j += 1)
		{
			char write = 0;
			if ( i == 0 || i == all_mazes[ 0].h - 1)
			{
				write = '#';
			}// if
			else if ( j == 0 || j == all_mazes[ 0].w - 1)
			{
				write = '#';
			}// else if
			else
			{
				write = '.';
			}// else
			all_mazes[ 0].blk[ i][ j] = write;
		}//for j
	}// for i


	return;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	printk(KERN_INFO "maze: ioctl cmd=%u arg=%lu.\n", cmd, arg);

	long retval = 0;

	switch ( cmd)
	{
	case MAZE_CREATE:
		// check if already used one slot
		int using = 0;
		for ( int i = 0; i < _MAZE_MAXUSER; i += 1)
		{
			if ( all_maze_attr[ i].host_process == current -> pid)
			{
				retval = -EEXIST;
				goto ioctl_ret;
			}// if
			if ( all_maze_attr[ i].host_process != 0)
			{
				using += 1;
			}// if
		}// for i

		// check for space
		if ( using == _MAZE_MAXUSER)
		{
			retval = -ENOMEM;
			goto ioctl_ret;
		}// if
		
		// read parameters
		coord_t dims = { 0};
		if ( copy_from_user( &dims, (void *)arg, sizeof(coord_t)))
		{
			retval = -EBUSY;
			goto ioctl_ret;
		}// if

		// check parameter values
		if ( dims.x > _MAZE_MAXX || dims.y > _MAZE_MAXY ||
			dims.x <= 0 || dims.y <= 0)
		{
			retval = -EINVAL;
			goto ioctl_ret;
		}// if
		
		printk( KERN_INFO "pid:%d, MAZE_CREATE (%d, %d)\n", current -> pid, dims.x, dims.y);
		generate_maze( using, dims);
		break;
	case MAZE_RESET:
		break;
	case MAZE_DESTROY:
		break;
	case MAZE_GETSIZE:
		break;
	case MAZE_MOVE:
		break;
	case MAZE_GETPOS:
		break;
	case MAZE_GETSTART:
		break;
	case MAZE_GETEND:
		break;
	default:
		retval = -ENOTTY;
		goto ioctl_ret;
		break;
	}// switch

ioctl_ret:
	return retval;
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
	char buf[ 128];

	// check the individual files
	for ( int i = 0; i < _MAZE_MAXUSER; i += 1)
	{
		memset( buf, 0, sizeof( buf));
		// choose the mutex lock
		struct mutex *using;
		switch ( i)
		{
		case 0:
			using = &maze1_lock;
			break;
		case 1:
			using = &maze2_lock;
			break;
		case 2:
			using = &maze3_lock;
			break;
		
		default:
			break;
		}// switch

		sprintf( buf, "#0%d: ", i);
		mutex_lock( using);
		if ( all_maze_attr[ i].host_process == 0)
		{
			strncat( buf, "vacancy\n", strlen("vacancy\n"));
			seq_printf(m, buf);
		}// if
		else
		{
			// print the maze
			seq_printf(m, buf);
			// #00: pid 75 - [19 x 19]: (3, 11) -> (17, 7) @ (3, 11)
			sprintf( buf, "pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n",
					all_maze_attr[ i].host_process,
					all_mazes[ i].w, all_mazes[ i].h,
					all_mazes[ i].sx, all_mazes[ i].sy,
					all_mazes[ i].ex, all_mazes[ i].ey,
					all_maze_attr[ i].player_pos.x, all_maze_attr[ i].player_pos.y);
			seq_printf(m, buf);

			// - 000: #################################
			for ( int j = 0; j < all_mazes[ i].h; j += 1)
			{
				memset( buf, 0, sizeof( buf));
				sprintf( buf, "- %03d: ", j);
				// the maze contents
				strncat( buf, all_mazes[ i].blk[ j], _MAZE_MAXX * sizeof(char));
				strncat( buf, "\n", sizeof(char));
				seq_printf( m, buf);
			}// for j
		}// else
		mutex_unlock( using);
		seq_printf(m, "\n");
	}// for i

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

	// init maze space
	memset( all_mazes, 0, sizeof( all_mazes));
	// init maze attr
	memset( all_maze_attr, 0, sizeof( all_maze_attr));

	// // test matrix
	// all_maze_attr[ 0].host_process = 69;
	// all_maze_attr[ 0].player_pos = (coord_t){ 2, 3};

	// all_mazes[ 0].w = 11;
	// all_mazes[ 0].h = 7;
	// for ( int i = 0; i < all_mazes[ 0].h; i += 1)
	// {
	// 	for ( int j = 0; j < all_mazes[ 0].w; j += 1)
	// 	{
	// 		char write = 0;
	// 		if ( i == 0 || i == all_mazes[ 0].h - 1)
	// 		{
	// 			write = '#';
	// 		}// if
	// 		else if ( j == 0 || j == all_mazes[ 0].w - 1)
	// 		{
	// 			write = '#';
	// 		}// else if
	// 		else
	// 		{
	// 			write = '.';
	// 		}// else
	// 		all_mazes[ 0].blk[ i][ j] = write;
	// 	}//for j
	// }// for i
	

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
