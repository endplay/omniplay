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
	int data;
	struct list_head list;
};

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
		kfree(fds);
        }
	kfree (pmonitor);
}

long xray_monitor_fillbuf (struct xray_monitor* pmonitor, struct monitor_data __user* buf, u_long entries)
{
	struct fd_struct* fds;
	u_long cnt = 0;

	list_for_each_entry (fds, &pmonitor->fds, list) {
		if (cnt < entries) {
			copy_to_user (&buf[cnt].fd, &fds->fd, sizeof(fds->fd));
			copy_to_user (&buf[cnt].data, &fds->data, sizeof(fds->data));
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

int xray_monitor_add_fd(struct xray_monitor* monitor, int fd, int data) {
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
	fds->fd = fd;
	fds->data = data;
	list_add (&(fds->list), &(monitor->fds));
	
	return 0;
}

int xray_monitor_remove_fd(struct xray_monitor* monitor, int fd) {
	struct fd_struct* fds;
	struct fd_struct* fds_safe;
	list_for_each_entry_safe (fds, fds_safe, &(monitor->fds), list) {
		if (fds->fd == fd) {
			list_del (&(fds->list));
			kfree(fds);
			return 1;
		}
	}
	return 0;
}

#endif 
