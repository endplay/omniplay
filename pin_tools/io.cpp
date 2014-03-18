#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <syscall.h>
#include "util.h"
#include <sys/socket.h>
#include <linux/net.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/stat.h>

#include <sys/wait.h>
#include <signal.h>

#include "xray_monitor.h"

// Defined in the makefile.rules
// #define ONLY_X

int copy_data = 1;
long bytes_read = 0;
long bytes_written = 0;
long global_syscall_cnt = 1;    // set to 1 to account for first exec that we miss

/* Files opened by this replay group */
FILE* filenames = NULL;
char stream_directory[256];
char stream_write_directory[256];
char stream_read_directory[256];

struct thread_data {
    u_long app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    uint64_t rg_id;     // record group id
    int record_pid;     // per thread record pid
    int syscall_cnt;    // per thread count of syscalls
    int sysnum;         // current syscall number
    int socketcall;     // current socketcall num if applicable
    u_long ignore_flag;
    void* syscall_info;

    FILE* stream_fp; // description of all the reads/writes going on
    long bytes_read;
    long bytes_written;
};

ADDRINT array[10000];

int dev_fd; // File descriptor for the replay device
TLS_KEY tls_key; // Key for accessing TLS. 
int first_thread = 1;

// mcc: the xray_monitor structure is just a wrapper around a 
//   linked list of file decriptors. If it turns out that there
//   are so many open fds, it might be more performant to 
//   change this to a hashtable.

/* List of open files*/
struct xray_monitor* open_fds = NULL;

/* List of open sockets */
struct xray_monitor* open_socks = NULL;

/* Just contains information about reads and writes */
FILE* meta_fp;

int get_record_pid(void);

ADDRINT find_static_address(ADDRINT ip)
{
    PIN_LockClient();
    IMG img = IMG_FindByAddress(ip);
    if (!IMG_Valid(img)) return ip;
    ADDRINT offset = IMG_LoadOffset(img);
    PIN_UnlockClient();
    return ip - offset;
}

struct read_info {
    int fd;
    void* buf;
    int read_size;
};

struct write_info {
    int fd;
    void* buf;
    int write_size;
};

struct writev_info {
    int fd;
    struct iovec* iov;
    int count;
};

#define MAX_PATH_LEN 256
struct open_info {
    char filename[MAX_PATH_LEN];
    int flags;
};

struct close_info {
    int fd;
};

struct mmap_info {
    void* addr;
    int length;
    int prot;
    int flags;
    int fd;
    off_t offset;
};

struct socket_info {
    int call;
    int domain;
    int type;
    int protocol;
    struct connect_info* ci;
    /* Contains information about the accepting socket.
     * NULL if this socket wasn't accepted */
    struct connect_info* accept_info; 
#ifdef ONLY_X
    int is_x;
#endif
};

struct connect_info {
    int fd;
    char path[MAX_PATH_LEN];    // for AF_UNIX
    int port;                   // for AF_INET/6
    struct in_addr sin_addr;    // for AF_INET
    struct in6_addr sin_addr6;  // for AF_INET6
};

struct accept_info {
    int fd;
    int domain;
    int type;
    int protocol;
    struct connect_info* accept_info;
    struct connect_info* connect_info;
};

struct dup_info {
    int oldfd;
    int newfd;
    int flags;
};

inline
void increment_syscall_cnt (struct thread_data* ptdata, int syscall_num)
{
    // ignore pthread syscalls, or deterministic system calls that we don't log (e.g. 243, 244)
    if (!(syscall_num == 17 || syscall_num == 31 || syscall_num == 32 || syscall_num == 35 || syscall_num == 44 || syscall_num == 53 || syscall_num == 56 || syscall_num == 98 || syscall_num == 243 || syscall_num == 244)) {
        /*
        if (ptdata->ignore_flag) {
            if (!(*(int *)(ptdata->ignore_flag))) {
                ptdata->syscall_cnt++;
                global_syscall_cnt++;
            }
        } else {
            global_syscall_cnt++;
            ptdata->syscall_cnt++;
        }
        */
        global_syscall_cnt++;
    }
}

void make_stream_directory(uint64_t rg_id) 
{
    snprintf(stream_directory, 256, "/tmp/io_%llu", rg_id);
    snprintf(stream_write_directory, 256, "%s/writes", stream_directory);
    snprintf(stream_read_directory, 256, "%s/reads", stream_directory);
    if (mkdir(stream_directory, 0755)) {
        if (errno == EEXIST) {
            fprintf(stderr, "directory already exists, using it: %s\n", stream_directory);
        } else {
            fprintf(stderr, "could not make directory %s\n", stream_directory);
            exit(-1);
        }
    }
    if (mkdir(stream_write_directory, 0755)) {
        if (errno == EEXIST) {
            fprintf(stderr, "writes directory already exists, using it: %s\n", stream_write_directory);
        } else {
            fprintf(stderr, "could not make directory %s\n", stream_write_directory);
            exit(-1);
        }
    }
    if (mkdir(stream_read_directory, 0755)) {
        if (errno == EEXIST) {
            fprintf(stderr, "reads directory already exists, using it: %s\n", stream_read_directory);
        } else {
            fprintf(stderr, "could not make directory %s\n", stream_read_directory);
            exit(-1);
        }
    }
}

int create_out_file(char* directory, uint64_t rg_id, int pid, int syscall, int offset, int size)
{
    int fd;
    char filename[256];
    snprintf(filename, 256, "%s/%llu_%d_%d", directory, rg_id, pid, syscall);
    fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        fprintf(stderr, "could not open out file %d, errno %d\n", fd, errno);
        return fd;
    }
    return fd;
}

void read_start(int fd, void* buf, int read_size) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    struct read_info* ri;
    ri = (struct read_info *) malloc(sizeof(struct read_info));

    ri->fd = fd;
    ri->buf = buf;
    ri->read_size = read_size;

    tdata->syscall_info = (void *) ri;
}

void read_stop(int rc) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    // successful read
    if (rc > 0) {
#ifdef ONLY_X
        struct read_info* ri = (struct read_info *) tdata->syscall_info;
        if (monitor_has_fd(open_socks, ri->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ri->fd);
            if (si->is_x) {
		fprintf (stderr, "is_x\n");
                //fprintf(meta_fp, "READ from X socket, size: %d, %s\n", rc, channel_name);
                //fflush(meta_fp);
                tdata->bytes_read += rc;
                bytes_read += rc;
            }
        }
#else
        char* channel_name = (char *) "--";
        int rcc;
        struct read_info* ri = (struct read_info *) tdata->syscall_info;
        assert (ri);
        if (monitor_has_fd(open_fds, ri->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, ri->fd);
            assert (oi);
            fprintf(stderr, "read from file %s\n", oi->filename);
            channel_name = oi->filename;
            fprintf(tdata->stream_fp, "READ %ld size: %d from %s\n", global_syscall_cnt, rc, oi->filename);
            fflush(tdata->stream_fp);
        } else if (monitor_has_fd(open_socks, ri->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ri->fd);
            assert (si);
            fprintf(tdata->stream_fp, "READ from socket %ld size: %d\n", global_syscall_cnt, rc);
            fflush(tdata->stream_fp);
            channel_name = (char *) "socket";
        } else {
            fprintf(stderr, "untracked read\n");
        }

        if (copy_data) {
            FILE* out_fp;
            int out_fd = create_out_file(stream_read_directory, tdata->rg_id, tdata->record_pid, global_syscall_cnt, 0, rc);
            assert (out_fd > 0);
            // write a header
            out_fp = fdopen(out_fd, "w");
            assert(out_fp);
            fprintf(out_fp, "%llu %d %ld %d %d %s\n",
                    tdata->rg_id, tdata->record_pid, global_syscall_cnt, 0, rc, channel_name);
            fflush(out_fp);
            rcc = write(out_fd, ri->buf, rc);
            if (rcc != rc) {
                fprintf(stderr, "could not write to read mirror file, expected %d got %d\n", rc, rcc);
            }
            fsync(out_fd);
            close(out_fd);
        }

        tdata->bytes_read += rc;
        bytes_read += rc;
#endif
    }

    free(tdata->syscall_info);
}

void write_start(int fd, void* buf, int write_size) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct write_info* wi;
    wi = (struct write_info *) malloc(sizeof(struct write_info));
    wi->fd = fd;
    wi->buf = buf;
    wi->write_size = write_size;

    tdata->syscall_info = (void *) wi;
}

void write_stop(int rc) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    // successful write
    if (rc > 0) {
        char* channel_name = (char *) "--";
#ifdef ONLY_X
        struct write_info* wi = (struct write_info *) tdata->syscall_info;
        if (monitor_has_fd(open_socks, wi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, wi->fd);
            if (si->is_x) {
                fprintf(tdata->stream_fp, "WRITE TO X socket, size: %d, %s\n", rc, channel_name);
                fflush(tdata->stream_fp);
                tdata->bytes_written += rc;
                bytes_written += rc;
            }
        }
#else
        struct write_info* wi = (struct write_info *) tdata->syscall_info;
        int rcc;
        if (monitor_has_fd(open_fds, wi->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, wi->fd);
            assert(oi);
            channel_name = oi->filename;
            fprintf(stderr, "write to file %s\n", oi->filename);
            fprintf(tdata->stream_fp, "WRITE %ld size: %d to %s\n", global_syscall_cnt, rc, oi->filename);
            fflush(tdata->stream_fp);
        } else if (monitor_has_fd(open_socks, wi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, wi->fd);
            assert(si);
            fprintf(stderr, "write to socket %d\n", wi->fd);
            if (si->accept_info) {
                fprintf(tdata->stream_fp, "WRITE to socket %ld size: %d (accepted socket)\n", global_syscall_cnt, rc);
                channel_name = (char *) "accepted_socket";
                if (si->domain == AF_UNIX) {
                    channel_name = si->accept_info->path;
                } else if (si->domain == AF_INET) {
                } else if (si->domain == AF_INET6) {
                }
            } else {
                fprintf(tdata->stream_fp, "WRITE to socket %ld size: %d\n", global_syscall_cnt, rc);
                if (si->domain == AF_UNIX) {
                    channel_name = si->ci->path;
                } else if (si->domain == AF_INET) {
                    // TODO
                } else if (si->domain == AF_INET6) {
                    // TODO
                }
            }
            fflush(tdata->stream_fp);
        } else {
            fprintf(stderr, "write to untracked fd\n");
        }

        if (copy_data) {
            FILE* out_fp;
            int out_fd = create_out_file(stream_write_directory, tdata->rg_id, tdata->record_pid, global_syscall_cnt, 0, rc);
            assert (out_fd > 0);
            // write a header
            out_fp = fdopen(out_fd, "w");
            fprintf(out_fp, "%llu %d %ld %d %d %s\n",
                    tdata->rg_id, tdata->record_pid, global_syscall_cnt, 0, rc, channel_name);
            fflush(out_fp);

            rcc = write(out_fd, wi->buf, rc);
            if (rcc != rc) {
                fprintf(stderr, "could not write to mirror file, expected %d got %d\n", rc, rcc);
            }
            fsync(out_fd);
            close(out_fd);
        }

        tdata->bytes_written += rc;
        bytes_written += rc;
#endif
    }

    free(tdata->syscall_info);
}

void writev_start(int fd, struct iovec* iov, int count)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct writev_info* wvi;
    wvi = (struct writev_info *) malloc(sizeof(struct writev_info));
    wvi->fd = fd;
    wvi->iov = iov;
    wvi->count = count;

    tdata->syscall_info = (void *) wvi;
}

void writev_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct writev_info* wvi = (struct writev_info *) tdata->syscall_info;
    int i;

    if (rc > 0) {
#ifdef ONLY_X
        if (monitor_has_fd(open_socks, wvi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, wvi->fd);
            if (si->is_x) {
                for (i = 0; i < wvi->count; i++) {
                    struct iovec* vi = (wvi->iov + i);
                    fprintf(tdata->stream_fp, "WRITEV %ld count %d size: %d to X\n", global_syscall_cnt, i, vi->iov_len);
                    fflush(tdata->stream_fp);
                }
            }
        }
        tdata->bytes_written += rc;
        bytes_written += rc;
#else
        if ((monitor_has_fd(open_fds, wvi->fd))) {
            FILE* fp = NULL;
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, wvi->fd);
            assert (oi);
            for (i = 0; i < wvi->count; i++) {
                struct iovec* vi = (wvi->iov + i);
                fprintf(tdata->stream_fp, "WRITEV %ld count %d size: %d to %s\n", global_syscall_cnt, i, vi->iov_len, oi->filename);
                if (copy_data && fp) {
                    unsigned int rcc;
                    rcc = write(fileno(fp), vi->iov_base, vi->iov_len);
                    if (rcc != vi->iov_len) {
                        fprintf(stderr, "could not write mirror stream %d bytes\n", rcc);
                    }
                    fflush(fp);
                }
            }
        } else if (monitor_has_fd(open_socks, wvi->fd)) {
            FILE* fp = NULL;
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, wvi->fd);
            assert (si);

            for (i = 0; i < wvi->count; i++) {
                struct iovec* vi = (wvi->iov + i);
                fprintf(tdata->stream_fp, "WRITEV %ld count %d size: %d to socket\n", global_syscall_cnt, i, vi->iov_len);
                if (copy_data && fp) {
                    unsigned int rcc;
                    rcc = write(fileno(fp), vi->iov_base, vi->iov_len);
                    if (rcc != vi->iov_len) {
                        fprintf(stderr, "could not write mirror stream %d bytes\n", rcc);
                    }
                    fflush(fp);
                }
            }
            fflush(tdata->stream_fp);
        } else {
            fprintf(stderr, "writev to untracked fd\n");
        }
        tdata->bytes_written += rc;
        bytes_written += rc;
#endif

        if (copy_data) {
            int rcc;
            int offset = 0;
            int out_fd = create_out_file(stream_directory, tdata->rg_id, tdata->record_pid, global_syscall_cnt, 0, rc);
            assert (out_fd > 0);
            for (i = 0; i < wvi->count; i++) {
                struct iovec* vi = (wvi->iov + i);
                // write a header
                fprintf(fdopen(out_fd, "w"), "%llu %d %ld %d %d\n",
                    tdata->rg_id, tdata->record_pid, global_syscall_cnt, offset, vi->iov_len);
                rcc = write(out_fd, vi->iov_base, vi->iov_len);
                if (rcc != rc) {
                    fprintf(stderr, "writev could not write to mirror file, expected %d got %d\n", rc, rcc);
                }
                offset += vi->iov_len;
            }
            fsync(out_fd);
            close(out_fd);
        }
    }

    free((void *) tdata->syscall_info);
}

void open_start(char* filename, int flags) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct open_info* oi;
    oi = (struct open_info *) malloc(sizeof(struct open_info));
    strncpy(oi->filename, filename, MAX_PATH_LEN);
    oi->flags = flags;

    tdata->syscall_info = (void *) oi;
}

void open_stop(int rc) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct open_info* oi = (struct open_info *) tdata->syscall_info;
    // on successful open
    if (rc > 0) {
        int cloexec = 0;
        if (copy_data) {
            char read_stream_name[256];
            char write_stream_name[256];
            // Make the stream filename start with the global syscall cnt
            snprintf(read_stream_name, 256, "/tmp/io/%ld_read", global_syscall_cnt);
            snprintf(write_stream_name, 256, "/tmp/io/%ld_write", global_syscall_cnt);
        }

        cloexec = oi->flags | O_CLOEXEC;
        fprintf(stderr, "Open add fd %d, cloexec %d\n", rc, cloexec);
        monitor_add_fd(open_fds, rc, cloexec, oi);
        tdata->syscall_info = 0;

        fprintf(filenames, "%ld %s\n", global_syscall_cnt, oi->filename);
        fflush(filenames);
    }

    if (tdata->syscall_info) {
        free(tdata->syscall_info);
    }
}

void close_start(int fd) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct close_info* ci;
    ci = (struct close_info *) malloc(sizeof(struct close_info));
    ci->fd = fd;

    tdata->syscall_info = (void *) ci;
}

void close_stop(int rc) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct close_info* ci = (struct close_info *) tdata->syscall_info;
    // sucessful close
    if (!rc) {
        if (monitor_has_fd(open_fds, ci->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, ci->fd);
            assert (oi);

            free(oi);
            monitor_remove_fd(open_fds, ci->fd);
        } else if (monitor_has_fd(open_socks, ci->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ci->fd);
            assert (si);

            if (si->ci) {
                free(si->ci);
            }
            if (si->accept_info) {
                free(si->accept_info);
            }
            free(si);
            monitor_remove_fd(open_socks, ci->fd);
        }
    }
    free(tdata->syscall_info);
}

void mmap_start(void* addr, int length, int prot, int flags, int fd, off_t offset) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct mmap_info* mi;
    mi = (struct mmap_info *) malloc(sizeof(struct mmap_info));

    mi->addr = addr;
    mi->length = length;
    mi->prot = prot;
    mi->flags = flags;
    mi->fd = fd;
    mi->offset = offset;

    tdata->syscall_info = (void *) mi;
}

void mmap_stop(void* rc) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (rc != MAP_FAILED) {
        int rcc;
        struct mmap_info* mi = (struct mmap_info *) tdata->syscall_info;
        FILE* fp = NULL;
        assert (mi);
        if (monitor_has_fd(open_fds, mi->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, mi->fd);
            assert (oi);
            fprintf(stderr, "mmaped file %s\n", oi->filename);
            fprintf(tdata->stream_fp, "MMAP %ld size: %d from %s\n", global_syscall_cnt, mi->length, oi->filename);
            fflush(tdata->stream_fp);
        } else if (mi->fd != -1) {
            fprintf(stderr, "untracked mmap\n");
        }

        if (copy_data && fp) {
            rcc = write(fileno(fp), rc, mi->length);
            if (rcc != mi->length) {
                fprintf(stderr, "could not write %d bytes, shadowing mmap\n", rcc);
            }
            fflush(fp);
        }
        tdata->bytes_read += mi->length;
        bytes_read += mi->length;
    }

    free(tdata->syscall_info);
}

void socket_start(int domain, int type, int protocol) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct socket_info* si;
    si = (struct socket_info *) malloc(sizeof(struct socket_info));
    memset(si, 0, sizeof(struct socket_info));
    si->call = SYS_SOCKET;
    si->domain = domain;
    si->type = type;
    si->protocol = protocol;

    tdata->syscall_info = (void *) si;
}

void socket_stop(int rc) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (rc > 0) {
        struct socket_info* si = (struct socket_info *) tdata->syscall_info;
        monitor_add_fd(open_socks, rc, 0, si);
    }

    free(tdata->syscall_info);
}

void connect_start(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (monitor_has_fd(open_socks, sockfd)) {
        struct socket_info* si = (struct socket_info*) monitor_get_fd_data(open_socks, sockfd);
        struct connect_info* ci = (struct connect_info *) malloc(sizeof(struct connect_info));
        memset(ci, 0, sizeof(struct connect_info));
        assert(si);

        ci->fd = sockfd;
        if (si->domain == AF_UNIX) {
            struct sockaddr_un* sun = (struct sockaddr_un*) addr;
	    if (addr->sa_family == AF_UNIX) {
		memcpy(ci->path, sun->sun_path, 108); // apparently 108 is the magic number
	    } else {
		fprintf (stderr, "unknown sa_family %d is not AF_UNIX len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_un));
		memcpy(ci->path, "UNK", 4);
	    }
        } else if (si->domain == AF_INET) {
	    if (addr->sa_family == AF_INET) {
		struct sockaddr_in* sin = (struct sockaddr_in*) addr;
		ci->port = htons(sin->sin_port);
		memcpy(&ci->sin_addr, &sin->sin_addr, sizeof(struct in_addr));
	    } else {
		fprintf (stderr, "unknown sa_family %d is not AF_INET len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_in));
		ci->port = 0;
		memcpy(&ci->sin_addr, "UNK", 4);
	    }
        } else if (si->domain == AF_INET6) {
	    if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6* sin6 = (struct sockaddr_in6*) addr;
		ci->port = htons(sin6->sin6_port);
		memcpy(&ci->sin_addr6, &sin6->sin6_addr, sizeof(struct in6_addr));
	    } else {
		fprintf (stderr, "unknown sa_family %d is not AF_INET6 len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_in6));
		ci->port = 0;
		memcpy(&ci->sin_addr6, "UNK", 4);
	    }
        } else {
            fprintf(stderr, "unsupport socket family %d\n", si->domain);
            tdata->syscall_info = 0;
            free(ci);
            return;
        }
        tdata->syscall_info = (void *) ci;
    }
}

void connect_stop(int rc) 
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    // successful connect
    if (!rc && tdata->syscall_info) {
        struct connect_info* ci = (struct connect_info *) tdata->syscall_info;
        struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ci->fd);
        assert(si);

        si->ci = ci;
        tdata->syscall_info = 0;
#ifdef ONLY_X
        if (si->domain == AF_UNIX) {
            char* c;
            c = ci->path;
            c += 1;
            if (strstr(ci->path, "tmp/.X11-unix/X") ||
                    strstr(c, "tmp/.X11-unix/X")) {
                fprintf(stderr, "connect to X11, fd %d\n", ci->fd);
                si->is_x = 1;
            }
        } else if (si->domain == AF_INET) {
            struct in_addr ina;
            // X port is 6010, address is 127.0.0.1
            if (!inet_pton(AF_INET, "127.0.0.1", &ina)) {
                assert(false);
            }
            fprintf(stderr, "connect to port %d\n", ci->port);
            if (ci->port == 6010 && ina.s_addr == ci->sin_addr.s_addr) {
                si->is_x = 1;
                fprintf(stderr, "connect to X11 (over ssh forwarding)\n");
            }
        }
#else
        if (si->domain == AF_UNIX) {
            char read_stream_name[256];
            char write_stream_name[256];
            fprintf(tdata->stream_fp, "CONNECT %ld AF_UNIX path %s\n", global_syscall_cnt, ci->path);
            fflush(tdata->stream_fp);

            if (copy_data) {
                snprintf(read_stream_name, 256, "/tmp/%ld_%s_read", global_syscall_cnt, ci->path);
                snprintf(write_stream_name, 256, "/tmp/%ld_%s_write", global_syscall_cnt, ci->path);
            }
        } else if (si->domain == AF_INET) {
            char read_stream_name[256];
            char write_stream_name[256];
            char straddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ci->sin_addr, straddr, INET_ADDRSTRLEN);
            fprintf(tdata->stream_fp, "CONNECT %ld AF_INET addr: %s port %d\n", global_syscall_cnt, straddr, ci->port);
            fflush(tdata->stream_fp);

            if (copy_data) {
                snprintf(read_stream_name, 256, "/tmp/%ld_%s_%d_read", global_syscall_cnt, straddr, ci->port);
                snprintf(write_stream_name, 256, "/tmp/%ld_%s_%d_write", global_syscall_cnt, straddr, ci->port);
            }
        } else if (si->domain == AF_INET6) {
            char read_stream_name[256];
            char write_stream_name[256];
            char straddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ci->sin_addr6, straddr, INET6_ADDRSTRLEN);
            fprintf(tdata->stream_fp, "CONNECT %ld AF_INET6 addr: %s port %d\n", global_syscall_cnt, straddr, ci->port);
            fflush(tdata->stream_fp);

            if (copy_data) {
                snprintf(read_stream_name, 256, "/tmp/%ld_%s_%d_read", global_syscall_cnt, straddr, ci->port);
                snprintf(write_stream_name, 256, "/tmp/%ld_%s_%d_write", global_syscall_cnt, straddr, ci->port);
            }
        }
#endif
    }
}

void accept_start(int sockfd, struct sockaddr* addr, socklen_t size)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (monitor_has_fd(open_socks, sockfd)) {
        struct accept_info* ai = (struct accept_info *) malloc(sizeof(struct accept_info));
        struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, sockfd);
        struct connect_info* accept_info = (struct connect_info *) malloc(sizeof(struct connect_info));
        struct connect_info* connect_info = (struct connect_info *) malloc(sizeof(struct connect_info));

        assert (si);

        memcpy(accept_info, si->ci, sizeof(struct connect_info));

        if (si->domain == AF_UNIX) {
            struct sockaddr_un* sun = (struct sockaddr_un*) addr;
            assert(addr->sa_family == AF_UNIX);
            
            strncpy(connect_info->path, sun->sun_path, MAX_PATH_LEN);
        } else if (si->domain == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*) addr;
            assert(addr->sa_family == AF_INET);
            connect_info->port = htons(sin->sin_port);
            memcpy(&connect_info->sin_addr, &sin->sin_addr, sizeof(struct in_addr));
        } else if (si->domain == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*) addr;
            assert(addr->sa_family == AF_INET6);
            connect_info->port = htons(sin6->sin6_port);
            memcpy(&connect_info->sin_addr6, &sin6->sin6_addr, sizeof(struct in6_addr));
        } else {
            fprintf(stderr, "accept on unsupported socket family %d\n", si->domain);
            tdata->syscall_info = 0;
            free(accept_info);
            free(connect_info);
            free(ai);
            return;
        }

        ai->fd = sockfd;
        ai->domain = si->domain;
        ai->type = si->type;
        ai->protocol = si->protocol;
        ai->accept_info = accept_info;
        ai->connect_info = connect_info;
        tdata->syscall_info = (void *) ai;
    }
}

void accept_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    // successful accept
    if (rc > 0 && tdata->syscall_info) {
        struct accept_info* ai = (struct accept_info *) tdata->syscall_info;
        struct socket_info* si = (struct socket_info *) malloc(sizeof(struct socket_info));

        si->call = SYS_ACCEPT;
        si->domain = ai->domain;
        si->type = ai->type;
        si->protocol = ai->protocol;
        si->ci = ai->connect_info;
        si->accept_info = ai->accept_info;

        monitor_add_fd(open_socks, rc, 0, si);

        free (tdata->syscall_info);
    }
}

void dup_start(int dup_type, int oldfd, int newfd, int flags)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct dup_info* di;
    di = (struct dup_info *) malloc(sizeof(struct dup_info));
    di->oldfd = oldfd;

    if (dup_type == 2) {
        di->newfd = newfd;
    } else if (dup_type == 3) {
        di->newfd = newfd;
        di->flags = flags;
    }

    tdata->syscall_info = (void *) di;
}

void dup_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct dup_info* di;
    di = (struct dup_info *) tdata->syscall_info;

    if (rc > 0) { // successful dup
        if (monitor_has_fd(open_fds, di->oldfd)) {
        }
    }
    free((void *) tdata->syscall_info);
}

void instrument_syscall_ret(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
        if (tdata->app_syscall != 999) tdata->app_syscall = 0;
    } else {
        fprintf (stderr, "instrument_syscall_ret: NULL tdata\n");
    }
    ADDRINT ret_value = PIN_GetSyscallReturn(ctxt, std);

    switch (tdata->sysnum) {
        case SYS_read:
            read_stop((int) ret_value);
            break;
        case SYS_write:
            write_stop((int) ret_value);
            break;
        case SYS_open:
#ifndef ONLY_X
            open_stop((int) ret_value);
#endif
            break;
        case SYS_close:
            close_stop((int) ret_value);
            break;
        case SYS_readv:
            break;
        case SYS_writev:
            writev_stop((int) ret_value);
            break;
        case SYS_mmap2:
#ifndef ONLY_X
            mmap_stop((void *) ret_value);
#endif
            break;
        case SYS_dup:
            dup_stop((int) ret_value);
            break;
        case SYS_dup3:
            break;
        case SYS_dup2:
            break;
        case SYS_fcntl:
            break;
        case SYS_socketcall:
            int call = tdata->socketcall;
            switch (call) {
                case SYS_SOCKET:
                    socket_stop((int) ret_value);
                    break;
                case SYS_CONNECT:
                    connect_stop((int) ret_value);
                    break;
                case SYS_SEND:
                case SYS_SENDTO:
                    write_stop((int) ret_value);
                    break;
                case SYS_RECV:
	        case SYS_RECVFROM:
                    read_stop((int) ret_value);
                    break;
                case SYS_BIND:
                    // TODO
                    connect_stop((int) ret_value);
                    break;
                case SYS_ACCEPT:
                    // TODO
                    accept_stop((int) ret_value);
                    break;
                default:
                    fprintf(stderr, "Unknown socket call %d\n", call);
            }
            break;
    }

    increment_syscall_cnt(tdata, tdata->sysnum);
    // reset the syscall number after returning from system call
    tdata->sysnum = 0;
    tdata->socketcall = 0;
}

// called before every application system call
void instrument_syscall(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2, ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{   
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
        int sysnum = (int) syscall_num;

        fprintf (stderr, "%ld Pid %d, tid %d, (record pid %d), %d: syscall num is %d\n", global_syscall_cnt, PIN_GetPid(), PIN_GetTid(), tdata->record_pid, tdata->syscall_cnt, (int) syscall_num);

        if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
            check_clock_before_syscall (dev_fd, (int) syscall_num);
        }
        tdata->sysnum = syscall_num;

        switch(sysnum) {
        case 31:
            tdata->ignore_flag = (u_long) syscallarg2;
            break;
        case SYS_execve:
        {
            char* program_name = (char *) syscallarg0;
            fprintf(stderr, "Trying to exec %s\n", program_name);
            break;
        }
        case SYS_read:
            read_start((int)syscallarg0, (void *)syscallarg1, (int)syscallarg2);
            break;
        case SYS_write:
            write_start((int)syscallarg0, (void *)syscallarg1, (int)syscallarg2);
            break;
        case SYS_writev:
            writev_start((int)syscallarg0, (struct iovec*)syscallarg1, (int)syscallarg2);
            break;
        case SYS_open:
            open_start((char *)syscallarg0, (int)syscallarg1);
            break;
        case SYS_close:
            close_start((int)syscallarg0);
            break;
        case SYS_mmap2:
            mmap_start((void*)syscallarg0, (int)syscallarg1, (int)syscallarg2, (int)syscallarg3,
                    (int)syscallarg4, (off_t)syscallarg5);
            break;
        case SYS_dup:
            dup_start(1, (int)syscallarg0, -1, -1);
            break;
        case SYS_dup2:
            dup_start(2, (int)syscallarg0, (int)syscallarg1, -1);
            break;
        case SYS_dup3:
            dup_start(3, (int)syscallarg0, (int)syscallarg1, (int)syscallarg2);
            break;
        case SYS_fcntl:
            {
                // TODO
                int cmd = (int)syscallarg1;
                if ((cmd | F_DUPFD) || (cmd | F_DUPFD_CLOEXEC)) {
                    fprintf(stderr, "fcntl dupfd not supported yet\n");
                }
                break;
            }
        case SYS_socketcall:
            int call = (int)syscallarg0;
            unsigned long *args = (unsigned long *)syscallarg1;
            tdata->socketcall = call;
            switch (call) {
                case SYS_SOCKET:
                    socket_start((int)args[0], (int)args[1], (int)args[2]);
                    break;
                case SYS_CONNECT:
                    connect_start((int)args[0], (struct sockaddr *)args[1], (socklen_t) args[2]);
                    break;
                case SYS_SEND:
                case SYS_SENDTO:
                    write_start((int)args[0], (void *) args[1], (int)args[2]);
                    break;
                case SYS_RECV:
                case SYS_RECVFROM:
                    read_start((int)args[0], (void *) args[1], (int)args[2]);
                    break;
                case SYS_SOCKETPAIR:
                    break;
                case SYS_BIND:
                    // TODO
                    connect_start((int)args[0], (struct sockaddr *)args[1], (socklen_t)args[2]);
                    break;
                case SYS_ACCEPT:
                    // TODO
                    accept_start((int)args[0], (struct sockaddr *)args[1], (socklen_t)args[2]);
                    break;
                default:
                    fprintf(stderr, "Unknown socket call %d\n", call);
            };
            break;
    }

    tdata->app_syscall = syscall_num;

    } else {
        fprintf (stderr, "instrumente_syscall: NULL tdata\n");
    }
}

void syscall_after (ADDRINT ip)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
        if (tdata->app_syscall == 999) {
            if (check_clock_after_syscall (dev_fd) == 0) {
            } else {
                fprintf (stderr, "Check clock failed\n");
            }
            tdata->app_syscall = 0;  
        }
    } else {
        fprintf (stderr, "syscall_after: NULL tdata\n");
    }
}

void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    int record_pid;
    fprintf(stderr, "AfterForkInChild\n");
    record_pid = get_record_pid();
    fprintf(stderr, "get record id %d\n", record_pid);
    tdata->record_pid = record_pid;
}

void track_inst(INS ins, void* data) 
{
    if(INS_IsSyscall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_syscall), IARG_SYSCALL_NUMBER, 
                    IARG_REG_VALUE, LEVEL_BASE::REG_EBX, 
                    IARG_SYSARG_VALUE, 0, 
                    IARG_SYSARG_VALUE, 1,
                    IARG_SYSARG_VALUE, 2,
                    IARG_SYSARG_VALUE, 3,
                    IARG_SYSARG_VALUE, 4,
                    IARG_SYSARG_VALUE, 5,
                    IARG_END);
    }
}

void track_trace(TRACE trace, void* data)
{
    // System calls automatically end a Pin trace.
    // So we can instrument every trace (instead of every instruction) to check to see if
    // the beginning of the trace is the first instruction after a system call.
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);
}

BOOL follow_child(CHILD_PROCESS child, void* data)
{
    // TODO: persist fd struct over an exec
    char** argv;
    char** prev_argv = (char**)data;
    int index = 0;

    fprintf(stderr, "following child...\n");

    /* the format of pin command would be:
     * pin_binary -follow_execv -t pin_tool new_addr*/
    int new_argc = 5;
    argv = (char**)malloc(sizeof(char*) * new_argc);

    argv[0] = prev_argv[index++];
    argv[1] = (char *) "-follow_execv";
    while(strcmp(prev_argv[index], "-t")) index++;
    argv[2] = prev_argv[index++];
    argv[3] = prev_argv[index++];
    argv[4] = (char *) "--";

    CHILD_PROCESS_SetPinCommandLine(child, new_argc, argv);

    fprintf(stderr, "returning from follow child\n");
    fprintf(stderr, "pin my pid is %d\n", PIN_GetPid());
    fprintf(stderr, "%d is application thread\n", PIN_IsApplicationThread());
    getppid();

    return TRUE;
}

int get_record_pid()
{
    //calling kernel for this replay thread's record log
    int record_log_id;

    record_log_id = get_log_id (dev_fd);
    if (record_log_id == -1) {
        int pid = PIN_GetPid();
        fprintf(stderr, "Could not get the record pid from kernel, pid is %d\n", pid);
        return pid;
    }
    return record_log_id;
}

void thread_start (THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    struct thread_data* ptdata;

    fprintf (stderr, "Start of threadid %d\n", (int) threadid);

    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    assert (ptdata);
    
    ptdata->app_syscall = 0;
    get_record_group_id(dev_fd, &ptdata->rg_id);
    ptdata->record_pid = get_record_pid();
    ptdata->syscall_cnt = 0;
    ptdata->ignore_flag = 0;

    ptdata->bytes_read = 0;
    ptdata->bytes_written = 0;

    if (first_thread) {
	    char stream_filename[256];
        make_stream_directory(ptdata->rg_id);

        snprintf(stream_filename, 256, "%s/streams_info_%d", stream_directory, ptdata->record_pid);
        ptdata->stream_fp = fopen(stream_filename, "w");

        if (!filenames) {
            char filename_file[256];
            snprintf(filename_file, 256, "%s/filenames", stream_directory);
            filenames = fopen(filename_file, "w");
            if (!filenames) {
                fprintf(stderr, "Could not create %s/filenames\n", stream_directory);
                exit(0);
            }
        }

        first_thread = 0;
    }

    PIN_SetThreadData (tls_key, ptdata, threadid);

    set_pin_addr (dev_fd, (u_long) ptdata);
}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    fprintf(stderr, "Pid %d (recpid %d, tid %d) thread fini\n", PIN_GetPid(), ptdata->record_pid, PIN_GetTid());
    fprintf(stderr, "thread %d bytes read %ld\n", ptdata->record_pid, ptdata->bytes_read);
    fprintf(stderr, "thread %d bytes written %ld\n", ptdata->record_pid, ptdata->bytes_written);
}

void fini(INT32 code, void* v) {
    fprintf(stderr, "bytes read %ld\n", bytes_read);
    fprintf(stderr, "bytes written %ld\n", bytes_written);
}

int main(int argc, char** argv) 
{    
    int rc;
    fprintf(stderr, "Starting io tool\n");

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "ERROR: could not initialize Pin?\n");
        exit(-1);
    }

    if (!open_fds) {
#ifndef ONLY_X
        struct open_info* oi;
#endif
        open_fds = new_xray_monitor(sizeof(struct open_info));
#ifndef ONLY_X
        // setup stdin/stdout/stderr fds
        oi = (struct open_info *) malloc(sizeof(struct open_info));
        strcpy(oi->filename, "stdin");
        oi->flags = 0;
        monitor_add_fd(open_fds, fileno(stdin), 0, oi);
        oi = (struct open_info *) malloc(sizeof(struct open_info));
        strcpy(oi->filename, "stdout");
        oi->flags = 0;
        monitor_add_fd(open_fds, fileno(stdout), 0, oi);
        oi = (struct open_info *) malloc(sizeof(struct open_info));
        strcpy(oi->filename, "stderr");
        oi->flags = 0;
        monitor_add_fd(open_fds, fileno(stderr), 0, oi);
#endif
    }

    if (!open_socks) {
        open_socks = new_xray_monitor(sizeof(struct socket_info));
    }

    // Intialize the replay device
    rc = devspec_init (&dev_fd);
    if (rc < 0) return rc;

    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);

    PIN_AddThreadStartFunction(thread_start, 0);
    PIN_AddThreadFiniFunction(thread_fini, 0);

    PIN_AddFiniFunction(fini, 0);

    PIN_AddFollowChildProcessFunction(follow_child, argv);
    INS_AddInstrumentFunction(track_inst, 0);

    // Register a notification handler that is called when the application
    // forks a new process
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);

    TRACE_AddInstrumentFunction (track_trace, 0);

    PIN_AddSyscallExitFunction(instrument_syscall_ret, 0);
    PIN_StartProgram();

    return 0;
}
