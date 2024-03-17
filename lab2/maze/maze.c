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

#include <linux/random.h>	// for get_random_u32
#include <linux/string.h>	// for memset
#include "maze.h"			// for maze things

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

// lock all mazes, performance is not that important
static maze_t all_mazes[ 3];
static DEFINE_MUTEX(maze_lock);

// internel kernel struct
typedef struct
{
	int host_process;
	coord_t player_pos;
} maze_attr;

static maze_attr all_maze_attr[ 3];


static int maze_dev_open(struct inode *i, struct file *f) {
	// printk(KERN_INFO "maze: device opened.\n");
	return 0;
}

static void maze_release( int location)
{
	memset( &all_mazes[ location], 0, sizeof( all_mazes[ location]));
	memset( &all_maze_attr[ location], 0, sizeof( all_maze_attr[ location]));
	return;
}

static int maze_dev_close(struct inode *i, struct file *f) {
	// printk(KERN_INFO "maze: device closed.\n");

	// check if held any mazes
	mutex_lock( &maze_lock);
	for ( int i = 0; i < _MAZE_MAXUSER; i += 1)
	{
		if ( all_maze_attr[ i].host_process == current -> pid)
		{
			// free the maze
			maze_release( i);
			break;
		}// if
	}// for i
	mutex_unlock( &maze_lock);

	return 0;
}

static int maze_check_usage( void)
{
	// return the location or _MAZE_MAXUSER if not found
	int location = _MAZE_MAXUSER;

	mutex_lock( &maze_lock);
	for ( int i = 0; i < _MAZE_MAXUSER; i += 1)
	{
		if ( current -> pid == all_maze_attr[ i].host_process)
		{
			location = i;
			break;
		}// if
	}// for i
	mutex_unlock( &maze_lock);

	return location;
}

static ssize_t maze_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	// only give the contents of the maze
	// change to number for maze layout 1 for wall, 0 for path
	ssize_t retval = 0;

	int using = maze_check_usage();
	if ( using == _MAZE_MAXUSER)
	{
		// no maze held
		retval = -EBADFD;
		goto read_ret;
	}// if

	// transfer line by line to not break frame size 2048 bytes
	char map[ _MAZE_MAXX];

	for ( int i = 0; i < all_mazes[ using].h; i += 1)
	{
		for ( int j = 0; j < all_mazes[ using].w; j += 1)
		{
			map[ j] = all_mazes[ using].blk[ i][ j] == '#';
		}// for j

		if ( copy_to_user( (void *)buf + *off, &map, all_mazes[ using].w * sizeof(char)))
		{
			retval = -EBUSY;
			goto read_ret;
		}// if
		retval += all_mazes[ using].w;
		*off += all_mazes[ using].w;
	}// for i 

read_ret:
	return retval;
}

static ssize_t maze_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	// printk(KERN_INFO "maze: write %zu bytes @ %llu.\n", len, *off);

	// check if maze is held
	ssize_t retval = 0;

	int using = maze_check_usage();
	if ( using == _MAZE_MAXUSER)
	{
		// no maze held
		retval = -EBADFD;
		goto write_ret;
	}// if

	// check given bytes
	if ( len % sizeof(coord_t) != 0)
	{
		retval = -EINVAL;
		goto write_ret;
	}// if

	int move_count = len / sizeof(coord_t);
	coord_t *given = kmalloc( len, GFP_KERNEL);
	
	if ( copy_from_user( given, buf, len))
	{
		retval = -EFAULT;
		goto write_clean;
	}// if
	
	coord_t total_offset = { 0};
	coord_t valid[ 4] = { (coord_t){ -1, 0}, (coord_t){ 0, -1}, (coord_t){ 1, 0}, (coord_t){ 0, 1}};
	
	// int counter = 0;
	// only move if valid, skip if not valid
	for ( int i = 0; i < move_count; i += 1)
	{
		// check for valid moves
		for ( int j = 0; j < 4; j += 1)
		{
			if ( valid[ j].x == given[ i].x && valid[ j].y == given[ i].y &&
				all_mazes[ using].blk[ all_maze_attr[ using].player_pos.y + total_offset.y + given[ i].y][ all_maze_attr[ using].player_pos.x + total_offset.x + given[ i].x] == '.')
			{
				total_offset.x += given[ i].x;
				total_offset.y += given[ i].y;
				// counter += 1;
				break;
			}// if
		}// for j
		// printk( KERN_INFO "%d: pos(%d, %d), mov(%d, %d)\n", counter, all_maze_attr[ using].player_pos.x + total_offset.x,
		// 																all_maze_attr[ using].player_pos.y + total_offset.y,
		// 																given[ i].x, given[ i].y);
	}// for i

	// printk( KERN_INFO "%d == %d?\n", move_count, counter);
	
	all_maze_attr[ using].player_pos.x += total_offset.x;
	all_maze_attr[ using].player_pos.y += total_offset.y;

write_clean:
	kfree( given);
	given = NULL;

write_ret:
	return len;
}

// still need work
static void generate_maze( int location, coord_t dims)
{
	// set outer parts
	all_mazes[ location].w = dims.x;
	all_mazes[ location].h = dims.y;

	// blank maze
	int *visited = kzalloc( sizeof(int) * dims.x * dims.y, GFP_KERNEL);
	char write;
	for ( int i = 0; i < dims.y; i += 1)
	{
		for ( int j = 0; j < dims.x; j += 1)
		{
			if ( i == 0 || j == 0 ||
				i == dims.y - 1 || j == dims.x - 1)
			{
				write = '#';
			}// if
			else if ( i % 2 == 0 && j % 2 == 0)
			{
				write = '#';
			}// else if
			else
			{
				write = '.';
			}// else
			
			all_mazes[ location].blk[ i][ j] = write;
			if ( write == '#')
			{
				visited[ dims.x * i + j] = 1;
			}// if
		}// for j
	}// for i
	
	// the real generation
	coord_t start = (coord_t){ 1, 1};
	coord_t direction[ 4] = { (coord_t){ 1, 0}, (coord_t){ 0, 1}, (coord_t){ -1, 0}, (coord_t){ 0, -1}};
	coord_t *stack = kzalloc( sizeof(coord_t) * dims.x * dims.y, GFP_KERNEL);
	int stack_top = 0;
	stack[ stack_top] = start;
	// stack_top += 1;
	// visited[ dims.x * start.y + start.x] = 1;
	coord_t temp;
	while ( stack_top != -1)
	{
		// pop the stack
		temp = stack[ stack_top];
		stack_top -= 1;

		// printk( KERN_INFO "before: (%d,%d) %d\n", temp.x, temp.y, stack_top);
		// check if visited
		if ( visited[ temp.y * dims.x + temp.x] == 1)
		{
			all_mazes[ location].blk[ temp.y][ temp.x] = '#';
			// printk( KERN_INFO "skip: (%d,%d) %d\n", temp.x, temp.y, visited[ temp.y * dims.x + temp.x]);
			continue;
		}// if
		all_mazes[ location].blk[ temp.y][ temp.x] = '.';
		visited[ temp.y * dims.x + temp.x] = 1;

		// random add neighbors
		// shuffle direction
		int targets[ 2];
		for ( int i = 0; i < 4; i += 1)
		{
			targets[ 0] = get_random_u32() % 4;
			targets[ 1] = get_random_u32() % 4;
			start = direction[ targets[ 0]];
			direction[ targets[ 0]] = direction[ targets[ 1]];
			direction[ targets[ 1]] = start;
		}// for i
		
		int deadend = 4;
		// add all to stack
		for ( int i = 0; i < 4; i += 1)
		{
			if ( visited[( temp.y + direction[ i].y) * dims.x + temp.x + direction[ i].x] == 0)
			{
				// add only not visited
				stack_top += 1;
				stack[ stack_top] = (coord_t){ temp.x + direction[ i].x, temp.y + direction[ i].y};
			}// if
			else
			{
				deadend -= 1;
			}// else
		}// for i
		
		if ( deadend == 0 && dims.y != 3)
		{
			all_mazes[ location].blk[ temp.y][ temp.x] = '#';
		}// if
		
		// printk( KERN_INFO "%d\n", stack_top);
	}// while
	kfree( stack);
	stack = NULL;
	kfree( visited);
	visited = NULL;

	// set start and end point
	// no values on boarders allowed
	temp = (coord_t){ 0, 0};
	while ( all_mazes[ location].blk[ temp.y][ temp.x] == '#')
	{
		temp.x = get_random_u32() % dims.x;
		temp.y = get_random_u32() % dims.y;
	}// while
	all_mazes[ location].ex = temp.x;
	all_mazes[ location].ey = temp.y;

	temp = (coord_t){ 0, 0};
	while ( all_mazes[ location].blk[ temp.y][ temp.x] == '#' ||
			( temp.x == all_mazes[ location].ex && temp.y == all_mazes[ location].ey))
	{
		temp.x = get_random_u32() % dims.x;
		temp.y = get_random_u32() % dims.y;
	}// while
	all_mazes[ location].sx = temp.x;
	all_mazes[ location].sy = temp.y;
	
	all_maze_attr[ location].player_pos = (coord_t){ all_mazes[ location].sx, all_mazes[ location].sy};
	return;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	// printk(KERN_INFO "maze: ioctl cmd=%u arg=%lu.\n", cmd, arg);

	long retval = 0;
	int using;
	coord_t dims = { 0};

	switch ( cmd)
	{
	case MAZE_CREATE:
		// read parameters
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
		
		// check if already used one slot
		using = maze_check_usage();
		if ( using != _MAZE_MAXUSER)
		{
			retval = -EEXIST;
			goto ioctl_ret;
		}// if

		mutex_lock( &maze_lock);
		// check for space and get the space usage
		for ( int i = 0; i < _MAZE_MAXUSER; i += 1)
		{
			if ( all_maze_attr[ i].host_process == 0)
			{
				using = i;
				all_maze_attr[ i].host_process = current -> pid;
				break;
			}// if
		}// for i
		mutex_unlock( &maze_lock);

		if ( using == _MAZE_MAXUSER)
		{
			retval = -ENOMEM;
			goto ioctl_ret;
		}// if
		
		// printk( KERN_INFO "pid:%d, MAZE_CREATE (%d, %d)\n", current -> pid, dims.x, dims.y);
		all_maze_attr[ using].host_process = current -> pid;
		generate_maze( using, dims);
		break;

	case MAZE_RESET:
		// check if held maze
		using = maze_check_usage();
		if ( using == _MAZE_MAXUSER)
		{
			// no maze held
			retval = -ENOENT;
			goto ioctl_ret;
		}// if
		
		all_maze_attr[ using].player_pos = (coord_t){ all_mazes[ using].sx, all_mazes[ using].sy};
		break;

	case MAZE_DESTROY:
		// check if held maze
		using = maze_check_usage();
		if ( using == _MAZE_MAXUSER)
		{
			// no maze held
			retval = -ENOENT;
			goto ioctl_ret;
		}// if

		maze_release( using);
		break;

	case MAZE_GETSIZE:
		// check if held maze
		using = maze_check_usage();
		if ( using == _MAZE_MAXUSER)
		{
			// no maze held
			retval = -ENOENT;
			goto ioctl_ret;
		}// if

		dims = (coord_t){ all_mazes[ using].w, all_mazes[ using].h};
		if ( copy_to_user((void *)arg, &dims, sizeof(coord_t)))
		{
			retval = -EBUSY;
			goto ioctl_ret;
		}// if		
		break;

	case MAZE_MOVE:
		// check if held maze
		using = maze_check_usage();
		if ( using == _MAZE_MAXUSER)
		{
			// no maze held
			retval = -ENOENT;
			goto ioctl_ret;
		}// if

		// get dims
		if ( copy_from_user( &dims, (void *)arg, sizeof(coord_t)))
		{
			retval = -EBUSY;
			goto ioctl_ret;
		}// if

		coord_t valid[ 4] = { (coord_t){ -1, 0}, (coord_t){ 0, -1}, (coord_t){ 1, 0}, (coord_t){ 0, 1}};
		for ( int i = 0; i < 4; i += 1)
		{
			if ( dims.x == valid[ i].x && dims.y == valid[ i].y &&
				all_mazes[ using].blk[ all_maze_attr[ using].player_pos.y + dims.y][ all_maze_attr[ using].player_pos.x + dims.x] == '.')
			{
				// one of the valid moves
				all_maze_attr[ using].player_pos.x += dims.x;
				all_maze_attr[ using].player_pos.y += dims.y;
				break;
			}// if
		}// for i
		break;

	case MAZE_GETPOS:
		// check if held maze
		using = maze_check_usage();
		if ( using == _MAZE_MAXUSER)
		{
			// no maze held
			retval = -ENOENT;
			goto ioctl_ret;
		}// if

		dims = all_maze_attr[ using].player_pos;
		if ( copy_to_user((void *)arg, &dims, sizeof(coord_t)))
		{
			retval = -EBUSY;
			goto ioctl_ret;
		}// if
		break;

	case MAZE_GETSTART:
		// check if held maze
		using = maze_check_usage();
		if ( using == _MAZE_MAXUSER)
		{
			// no maze held
			retval = -ENOENT;
			goto ioctl_ret;
		}// if

		dims = (coord_t){ all_mazes[ using].sx, all_mazes[ using].sy};
		if ( copy_to_user((void *)arg, &dims, sizeof(coord_t)))
		{
			retval = -EBUSY;
			goto ioctl_ret;
		}// if
		break;

	case MAZE_GETEND:
		// check if held maze
		using = maze_check_usage();
		if ( using == _MAZE_MAXUSER)
		{
			// no maze held
			retval = -ENOENT;
			goto ioctl_ret;
		}// if

		dims = (coord_t){ all_mazes[ using].ex, all_mazes[ using].ey};
		if ( copy_to_user((void *)arg, &dims, sizeof(coord_t)))
		{
			retval = -EBUSY;
			goto ioctl_ret;
		}// if
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

		sprintf( buf, "#0%d: ", i);
		mutex_lock( &maze_lock);
		if ( all_maze_attr[ i].host_process == 0)
		{
			// no user in this part
			mutex_unlock( &maze_lock);
			strncat( buf, "vacancy\n", strlen("vacancy\n"));
			seq_printf(m, buf);
		}// if
		else
		{
			// only user is this process
			mutex_unlock( &maze_lock);

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
				// overwrite the special points
				if ( all_mazes[ i].ey == j)
				{
					// end point is on this line
					int offset = strlen("- %03d: ");
					buf[ offset + all_mazes[ i].ex] = 'E';
				}// if
				if ( all_mazes[ i].sy == j)
				{
					// start point is on this line
					int offset = strlen("- %03d: ");
					buf[ offset + all_mazes[ i].sx] = 'S';
				}// if
				if ( all_maze_attr[ i].player_pos.y == j)
				{
					// player point is on this line
					int offset = strlen("- %03d: ");
					buf[ offset + all_maze_attr[ i].player_pos.x] = '*';
				}// if
				
				strncat( buf, "\n", sizeof(char));
				seq_printf( m, buf);
			}// for j
		}// else
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
