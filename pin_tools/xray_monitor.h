#ifndef XRAY_MONITOR_H
#define XRAY_MONITOR_H

#include "list.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DEBUG_PRINT

/* A monitor is a struct that keeps track of fds that we want to monitor */
struct xray_monitor {
    // TODO(mcc): add fields for functions pointers to serialize and deserialize
    // the data field
    int data_len; 
    void (*free_func)(void*);
    struct list_head fds;   // fds to monitor
};

// A structure to hold fds
struct fd_struct {
    int fd;
    int cloexec;      // flag to see if this fd will be closed on exec
    void* data;
    struct list_head list;
};

// Prototypes
struct xray_monitor* new_xray_monitor(int data_len);
int pnew_xray_monitor(struct xray_monitor*, int data_len);
int monitor_has_fd(struct xray_monitor*, int fd);
int monitor_add_fd(struct xray_monitor*, int fd, int cloexec, void* data);
// TODO(mcc): free the data
int monitor_remove_fd(struct xray_monitor*, int fd);
int monitor_size(struct xray_monitor*);

// Removes all fd's that have set cloexec
void monitor_remove_cloexec(struct xray_monitor*);

// If the fd is being monitored, it sets the cloexec flag
int monitor_set_cloexec(struct xray_monitor*, int fd, int cloexec);
int monitor_get_cloexec(struct xray_monitor*, int fd);

// Equality check
// Is only used really for testing
int monitor_is_equal(struct xray_monitor* xrm1, struct xray_monitor* xrm2);

// Serialize a monitor and put the serial bytes into bytes
int monitor_serialize(struct xray_monitor*, void** bytes);
int monitor_serialize_to_file(const char* filename, struct xray_monitor*);

// Deserialize a monitory from the bytes to the struct
int monitor_deserialize(struct xray_monitor**, void* bytes);
int monitor_deserialize_from_file(const char* filename, struct xray_monitor**);

void* monitor_get_fd_data(struct xray_monitor*, int fd);

int pnew_xray_monitor(struct xray_monitor* xrm, int data_len) {
    INIT_LIST_HEAD (&xrm->fds);
    xrm->data_len = data_len;
    
    return 0;
}

struct xray_monitor* new_xray_monitor(int data_len) {
    struct xray_monitor* monitor;
    monitor = (struct xray_monitor*) malloc(sizeof(struct xray_monitor));

    monitor->data_len = data_len;
    INIT_LIST_HEAD (&monitor->fds);

    return monitor;
}

int monitor_has_fd(struct xray_monitor* monitor, int fd) {
    struct fd_struct* fds;
    list_for_each_entry (fds, &monitor->fds, list) {
        if (fds->fd == fd) {
            return 1;
        }
    }
    return 0;
}

int monitor_foreach(struct xray_monitor* monitor, void (*iter_func)(void* data)) {
    struct fd_struct* fds;
    list_for_each_entry (fds, &monitor->fds, list) {
        iter_func(fds->data);
    }
    return 0;
}

/**
 * Add an fd to monitor.
 *
 * If the fd already exists in the list, we set the cloexec flag to the new cloexec flag.
 */
int monitor_add_fd(struct xray_monitor* monitor, int fd, int cloexec, void* data) {
    struct fd_struct* fds;

    // if it's already in here, remove it
    if (monitor_has_fd(monitor, fd)) {
        monitor_remove_fd(monitor, fd);
    }

    // else add it
    fds = (struct fd_struct*) malloc(sizeof(struct fd_struct));
    fds->fd = fd;
    fds->cloexec = cloexec;
    fds->data = data;

    list_add (&fds->list, &monitor->fds);
    return 0;
}

int monitor_remove_fd(struct xray_monitor* monitor, int fd) {
    struct fd_struct* fds;
    struct fd_struct* fds_safe;
    list_for_each_entry_safe (fds, fds_safe, &monitor->fds, list) {
        if (fds->fd == fd) {
            list_del (&fds->list);
            free(fds);
            return 1;
        }
    }
    return 0;
}

// An order n operation because we need to traverse the linked list
// Probably could save this as a bit in the monitor, but it seems
// like an infrequently used operation.
int monitor_size(struct xray_monitor* monitor) {
    int size = 0;
    struct fd_struct* fds;
    list_for_each_entry (fds, &monitor->fds, list) {
        size++;
    }
    return size;
}

void monitor_remove_cloexec(struct xray_monitor* monitor) {
    struct fd_struct* fds;
    struct fd_struct* fds_safe;
    list_for_each_entry_safe (fds, fds_safe, &monitor->fds, list) {
        if (fds->cloexec == 1) {
            list_del (&fds->list);
            free(fds);
        }
    }
}

int monitor_set_cloexec(struct xray_monitor* monitor, int fd, int cloexec) {
    struct fd_struct* fds;
    struct fd_struct* fds_safe;
    list_for_each_entry_safe (fds, fds_safe, &monitor->fds, list) {
        if (fds->fd == fd) {
            fds->cloexec = cloexec;
            return 0;
        }
    }
    return -1;
}

int monitor_get_cloexec(struct xray_monitor* monitor, int fd) {
    struct fd_struct* fds;
    struct fd_struct* fds_safe;
    list_for_each_entry_safe (fds, fds_safe, &monitor->fds, list) {
        if (fds->fd == fd) {
            return fds->cloexec;
        }
    }
    return 0;
}

int monitor_serialize(struct xray_monitor* monitor, void** bytes) {
    void* index; // index into the bytes array
    int size_bytes;
    int num_fd_structs;
    struct fd_struct* fds;
    num_fd_structs = monitor_size(monitor);

    /* Format:
    *     (int) - num of fd structs
    *     (int) - length of data field
    *     (byte[]) fd structs
    *     (byte[]) data
    */
    size_bytes = 2*sizeof(int);
    size_bytes += (num_fd_structs * sizeof(struct fd_struct));
    size_bytes += (num_fd_structs * monitor->data_len);
    index = (void *) malloc(size_bytes);
    *bytes = index;

    fprintf(stdout, "index is %p\n", index);

    memcpy(index, &num_fd_structs, sizeof(int));
    index = (void *)((u_long)(index) + sizeof(int));

    memcpy(index, &monitor->data_len, sizeof(int));
    index = (void *)((u_long)(index) + sizeof(int));

    if (num_fd_structs == 0) {
        return size_bytes;
    }

    list_for_each_entry (fds, &monitor->fds, list) {
        memcpy(index, fds, sizeof(struct fd_struct));
        index = (void *)((u_long)(index) + sizeof(struct fd_struct));
    }

    list_for_each_entry (fds, &monitor->fds, list) {
        memcpy(index, fds->data, monitor->data_len);
        index = (void *)((u_long)(index) + monitor->data_len);
    }

    return size_bytes;
}

int monitor_serialize_to_file(const char* filename, struct xray_monitor* xrm)
{
    int size_monitor;
    void* ptr;
    size_monitor = monitor_serialize(xrm, &ptr);
    if (size_monitor < 0) {
        fprintf(stderr, "could not serialize error monitor\n");
        return -1;
    }
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        fprintf(stderr, "Error creating error monitor file %s\n", filename);
        return -1;
    }
    int rc = write(fd, ptr, size_monitor);
    if (rc != size_monitor) {
        fprintf(stderr, "Wrote %d bytes, expected %d bytes\n", rc, size_monitor);
        return -1;
    }
    close(fd);
    return 0;
}

int monitor_deserialize(struct xray_monitor** pmonitor, void* bytes) {
    void* index; // index into the bytes array
    int size_bytes;
    int data_len;
    void* data_array;
    int num_fd_structs;
    struct fd_struct* fds;
    struct xray_monitor* monitor;
    int i;

    index = bytes;
    fprintf(stdout, "index is %p\n", index);

    num_fd_structs = *(int *)bytes;
    if (num_fd_structs < 0) {
        fprintf(stderr, "deserialize monitor: num fd structs less than 0?\n");
        return -1;
    }
    fprintf(stderr, "monitor_deserialize: %d num_fd_structs\n", num_fd_structs);
    index = (void *)((u_long)(index) + sizeof(int));

    data_len = *(int *)index;
    if (num_fd_structs < 0) {
        fprintf(stderr, "deserialize monitor: data_len less than 0?\n");
        return -1;
    }
    fprintf(stderr, "monitor_deserialize: %d data_len\n", data_len);
    index = (void *)((u_long)(index) + sizeof(int));

    size_bytes = 2*sizeof(int);
    size_bytes += (num_fd_structs * sizeof(struct fd_struct));
    size_bytes += (num_fd_structs * data_len);

    // OK, create a new monitor
    *pmonitor = new_xray_monitor(data_len);
    monitor = *pmonitor;

    data_array = (void *)((u_long)(index) + (num_fd_structs * sizeof(struct fd_struct)));
    for (i = 0; i < num_fd_structs; i++) {
        void* data_ptr;
        data_ptr = (data_len ? malloc(data_len) : NULL);
        if (data_ptr) memcpy(data_ptr, (void *)((u_long)(data_array) + (i*data_len)), data_len);
        fds = (struct fd_struct *) index;
        monitor_add_fd(monitor, fds->fd, fds->cloexec, data_ptr);
        fprintf(stderr, "deserialize monitor: added back fd %d\n", fds->fd);
        index = (void *)((u_long)(index) + sizeof(struct fd_struct));
    } 

    return size_bytes;
}

int monitor_is_equal(struct xray_monitor* xrm1, struct xray_monitor* xrm2) {

    struct fd_struct* fds;

    list_for_each_entry (fds, &xrm1->fds, list) {
        if (!monitor_has_fd(xrm2, fds->fd)) {
            return 1;
        } else {
            if (monitor_get_cloexec(xrm2, fds->fd) != fds->cloexec) {
                return 1;
            }
        }
    }

    list_for_each_entry (fds, &xrm2->fds, list) {
        if (!monitor_has_fd(xrm1, fds->fd)) {
            return -1;
        } else {
            if (monitor_get_cloexec(xrm1, fds->fd) != fds->cloexec) {
                return -1;
            }
        }
    }

    if (monitor_size(xrm1) != monitor_size(xrm2)) return 1;

    return 0;
}

int monitor_deserialize_from_file(const char* filename, struct xray_monitor** pxrm)
{
    int fd = open(filename, O_RDONLY, 0644);
    if (fd == -1) {
        fprintf(stderr, "could not open serialized monitor, filename %s\n", filename);
        return -1;
    } 
    struct stat buf;
    int rc = fstat(fd, &buf);
    if (rc) {
        fprintf(stderr, "could not fstat serialized  monitor, filename: %s\n", filename);
        return -1;
    }
    int file_size = buf.st_size;
    void* ptr = malloc(file_size);

    rc = read(fd, ptr, file_size);
    if (rc != file_size) {
        fprintf(stderr, "could not read serialized monitor, expected %d bytes, got %d bytes\n", file_size, rc);
        return -1;
    }
    rc = monitor_deserialize(pxrm, ptr);
    if (rc != file_size) {
        fprintf(stderr, "[WARN] monitor size %d does not match seralized file size %d\n", rc, file_size);
    }

    free(ptr);

    return 0;
}

void* monitor_get_fd_data(struct xray_monitor* xrm, int fd)
{
    struct fd_struct* fds;
    list_for_each_entry (fds, &xrm->fds, list) {
        if (fds->fd == fd) {
            return fds->data;
        }
    }
    return NULL;

}

#endif // end include guard XRAY_MONITOR_H
