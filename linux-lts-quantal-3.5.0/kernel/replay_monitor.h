#ifndef XRAY_MONITOR_H
#define XRAY_MONITOR_H

#include <linux/kernel.h>
#include <linux/list.h>

/* A monitor is a struct that keeps track of fds that we want to monitor */
struct xray_monitor {
	int size;
	struct list_head fds;   // fds to monitor
};

// A structure to hold fds
struct fd_struct {
	int fd;
	int type;
	int data;
	char* channel;
	struct list_head list;
};

#define MONITOR_FILE   0
#define MONITOR_SOCKET 1

struct xray_monitor* new_xray_monitor(void) {
	struct xray_monitor* monitor;
	monitor = (struct xray_monitor*) kmalloc(sizeof(struct xray_monitor), GFP_KERNEL);
	memset(monitor, 0, sizeof(struct xray_monitor));
	
	monitor->size = 0;
	INIT_LIST_HEAD (&(monitor->fds));
	
	return monitor;
}

void xray_monitor_destroy (struct xray_monitor* pmonitor)
{
	struct fd_struct* fds;
	struct fd_struct* fds_safe;
	
	list_for_each_entry_safe (fds, fds_safe, &(pmonitor->fds), list) {
		list_del (&fds->list);
		if (fds->channel) kfree (fds->channel);
		kfree(fds);
        }
	kfree (pmonitor);
}

long xray_monitor_fillbuf (struct xray_monitor* pmonitor, struct monitor_data __user* buf, u_long entries)
{
	struct fd_struct* fds;
	u_long cnt = 0;
	struct monitor_data m;

	list_for_each_entry (fds, &pmonitor->fds, list) {
		if (cnt < entries) {
			m.fd = fds->fd;
			m.type = fds->type;
			m.data = fds->data;
			if (fds->channel && strlen(fds->channel) < sizeof(m.channel)) {
				strcpy (m.channel, fds->channel);
			} else {
				m.channel[0] = '\0';
			}
			copy_to_user (&buf[cnt], &m, sizeof(struct monitor_data));
			cnt++;
		} else {
			return -E2BIG;
		}
	}
	return cnt;
}

int xray_monitor_has_fd(struct xray_monitor* monitor, int fd) {
	struct fd_struct* fds; 
	list_for_each_entry (fds, &monitor->fds, list) {
		if (fds->fd == fd) {
			return 1;
		}
	}
	return 0;
}

int xray_monitor_add_fd(struct xray_monitor* monitor, int fd, int type, int data, const char* channel) {
	struct fd_struct* fds;
	
#ifdef REPLAY_PARANOID
	// if it's already in here, remove it
	if (monitor_has_fd(monitor, fd)) {
		printk(stderr, "WARN -- monitor already has fd %d\n", fd);
		monitor_remove_fd(monitor, fd);
	}
#endif

	// else add it
	fds = (struct fd_struct*) kmalloc(sizeof(struct fd_struct), GFP_KERNEL);
	if (fds == NULL) return -1;
	fds->fd = fd;
	fds->type = type;
	fds->data = data;
	if (channel) {
		fds->channel = kmalloc(strlen(channel)+1, GFP_KERNEL);
		if (fds->channel == NULL) {
			kfree (fds);
			return -1;
		}
		strcpy (fds->channel, channel);
	} else {
		fds->channel = NULL;
	}
	list_add (&(fds->list), &(monitor->fds));
	
	return 0;
}

int xray_monitor_remove_fd(struct xray_monitor* monitor, int fd) {
	struct fd_struct* fds;
	struct fd_struct* fds_safe;
	list_for_each_entry_safe (fds, fds_safe, &(monitor->fds), list) {
		if (fds->fd == fd) {
			list_del (&(fds->list));
			if (fds->channel) kfree (fds->channel);
			kfree(fds);
			return 1;
		}
	}
	return 0;
}

int checkpoint_xray_monitor(struct xray_monitor *monitor, struct file *cfile, loff_t *ppos) { 
	
	int copyed, cnt = 0;
	struct fd_struct* fds; 


	list_for_each_entry (fds, &monitor->fds, list) { 
		cnt++; 
	}
	
	copyed = vfs_write(cfile, (char *) &cnt, sizeof(cnt), ppos);
	if (copyed != sizeof(cnt)) {
		printk ("checkpoint_xray_monitor: tried to write count, got rc %d\n", copyed);
		return -EINVAL;
	}


	list_for_each_entry (fds, &monitor->fds, list) {		
		copyed = vfs_write(cfile, (char *) &fds->fd, sizeof(fds->fd), ppos);
		if (copyed != sizeof(fds->fd)) {
			printk ("checkpoint_xray_monitor tried to write fd, got rc %d\n", copyed);
			return -EINVAL;
		}
		copyed = vfs_write(cfile, (char *) &fds->type, sizeof(fds->type), ppos);
		if (copyed != sizeof(fds->type)) {
			printk ("checkpoint_xray_monitor tried to write type, got rc %d\n", copyed);
			return -EINVAL;
		}
		copyed = vfs_write(cfile, (char *) &fds->data, sizeof(fds->data), ppos);
		if (copyed != sizeof(fds->data)) {
			printk ("checkpoint_xray_monitor tried to write data, got rc %d\n", copyed);
			return -EINVAL;
		}

		if (fds->channel) {
			cnt = strlen(fds->channel);
			copyed = vfs_write(cfile, (char *)&cnt, sizeof(cnt), ppos);
			if (copyed != sizeof(strlen(fds->channel))) { 
				printk ("checkpoint_xray_monitor tried to write data, got rc %d\n", copyed);
				return -EINVAL;
			}		       
			copyed = vfs_write(cfile, fds->channel, cnt, ppos);
			if (copyed != cnt) { 
				printk ("checkpoint_xray_monitor can't write channel, got rc %d\n", copyed);
				return -EINVAL;
			}
		}
		else { 
			cnt = 0;
			copyed = vfs_write(cfile, (char *)&cnt, sizeof(cnt), ppos);
			if (copyed != sizeof(int)) { 
				printk ("checkpoint_xray_monitor tried to write zero, got rc %d\n", copyed);
				return -EINVAL;
			}
		}
	}

	return 0;	
}


int restore_xray_monitor(struct xray_monitor *monitor, struct file *cfile, loff_t *ppos) { 

	int copyed, cnt, fd, type, data, size, i;
	char channel[256]; 

	copyed = vfs_read(cfile, (char *) &cnt, sizeof(cnt), ppos);
	if (copyed != sizeof(cnt)) {
		printk ("restore_replay_cache_files: tried to read count, got rc %d\n", copyed);
		return copyed;
	}
	for (i = 0; i < cnt; i++) {

		copyed = vfs_read(cfile, (char *) &fd, sizeof(fd), ppos);
		if (copyed != sizeof(fd)) {
			printk ("restore_xray_monitor: tried to read fd, got rc %d\n", copyed);
			return copyed;
		}
		copyed = vfs_read(cfile, (char *) &type, sizeof(fd), ppos);
		if (copyed != sizeof(type)) {
			printk ("restore_xray_monitor: can't read type, got rc %d\n", copyed);
			return copyed;
		}
		copyed = vfs_read(cfile, (char *) &data, sizeof(fd), ppos);
		if (copyed != sizeof(data)) {
			printk ("restore_xray_monitor: can't read data, got rc %d\n", copyed);
			return copyed;
		}
		copyed = vfs_read(cfile, (char *) &size, sizeof(size), ppos);
		if (copyed != sizeof(size)) {
			printk ("restore_xray_monitor: can't read chsize, got rc %d\n", copyed);
			return copyed;
		}

		if (size > 0) { 
			copyed = vfs_read(cfile, channel, size, ppos);
			if (copyed != size) {
				printk ("restore_xray_monitor: can't read channel, got rc %d\n", copyed);
				return copyed;
			}
			channel[size] = '\0';
			
		}		
		
		xray_monitor_add_fd(monitor,fd,type, data, channel);
	}	       
	return 0;
}

#endif 
