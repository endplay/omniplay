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
#include <linux/net.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include <sys/wait.h>
#include <signal.h>

#include "xray_monitor.h"

// Defined in the makefile.rules
// #define ONLY_X

//#define DEBUG_PRINT fprintf
#define DEBUG_PRINT(...)

int copy_data = 1;
long bytes_read = 0;
long bytes_written = 0;
long global_syscall_cnt = 1;    // set to 1 to account for first exec that we miss
/* Toggle between which syscall count to use */
#define SYSCALL_CNT tdata->syscall_cnt
// #define SYSCALL_CNT global_syscall_cnt
long include_mmap_exec = 0;

/* Files opened by this replay group */
FILE* filenames = NULL;
FILE* stream_fp = NULL; // description of all the reads/writes going on
FILE* times_fp = NULL; // syscall cnt -> time (for gettimeofday)
char stream_directory[256];
char stream_write_directory[256];
char stream_read_directory[256];
KNOB<string> KnobDirectoryPrefix(KNOB_MODE_WRITEONCE, "pintool", "d", "/tmp",
        "top-level directory to make the io directory");
KNOB<BOOL> KnobIncludeExMmap(KNOB_MODE_WRITEONCE, "pintool", "x", "0",
        "Include mmaps with PROT_EXEC as input");

struct thread_data {
    u_long app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    uint64_t rg_id;     // record group id
    int record_pid;     // per thread record pid
    long syscall_cnt;    // per thread count of syscalls
    int sysnum;         // current syscall number
    int socketcall;     // current socketcall num if applicable
    u_long ignore_flag;
    void* syscall_info;

    long bytes_read;
    long bytes_written;
};

int dev_fd; // File descriptor for the replay device
TLS_KEY tls_key; // Key for accessing TLS. 
int first_thread = 1;
int child = 0;

// mcc: the xray_monitor structure is just a wrapper around a 
//   linked list of file decriptors. If it turns out that there
//   are so many open fds, it might be more performant to 
//   change this to a hashtable.

/* List of open files*/
struct xray_monitor* open_fds = NULL;

/* List of open sockets */
struct xray_monitor* open_socks = NULL;

int get_record_pid(void);

// state to be saved and restored after an exec.
// Saved in /tmp/saved_state.<replay_group_id>
struct save_state {
    uint64_t rg_id; // for verification purposes, ask the kernel for these!
    int record_pid; // (see above)

    long global_syscall_cnt;
};

int save_state_to_disk(struct thread_data* ptdata) {
    int fd;
    int rc;
    char state_filename[256];
    struct save_state state;

    // record the state
    memcpy(&state.rg_id, &ptdata->rg_id, sizeof(uint64_t));
    state.record_pid = ptdata->record_pid;
    state.global_syscall_cnt = global_syscall_cnt;

    snprintf(state_filename, 256, "/tmp/%llu.state", ptdata->rg_id);
    fd = open(state_filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    rc = write(fd, &state, sizeof(struct save_state));
    if (rc != sizeof(struct save_state)) {
        fprintf(stderr, "Could not write saved state to %s, errno %d\n", state_filename, errno);
        return -1;
    }
    close(fd);
    return 0;
}

int restore_state_from_disk(struct thread_data* ptdata) {
    int fd;
    int rc;
    char state_filename[256];
    struct save_state state;
    
    snprintf(state_filename, 256, "/tmp/%llu.state", ptdata->rg_id);

    fprintf(stderr, "Restore state from %s\n", state_filename);
    if (access(state_filename, F_OK)) {
        fprintf(stderr, "State file does not exist, no state to restore\n");
        return 0;
    }

    fd = open(state_filename, O_RDONLY);
    rc = read(fd, &state, sizeof(struct save_state));
    if (rc != sizeof(struct save_state)) {
        fprintf(stderr, "Could not read in saved state from %s, errno %d\n", state_filename, errno);
        close(fd);
        return -1;
    }
    close(fd);

    // now, restore the state
    // but let's do some verification checks first.
    if (ptdata->rg_id != state.rg_id) {
        fprintf(stderr, "Record group is different?!\n");
        return -1;
    }
    if (ptdata->record_pid != state.record_pid) {
        fprintf(stderr, "Record pid is different?!\n");
        return -1;
    }
    global_syscall_cnt = state.global_syscall_cnt;
    if (global_syscall_cnt < 0) {
        fprintf(stderr, "something went wrong here, global_syscall_cnt is %ld\n", global_syscall_cnt);
        return -1;
    }

    /* We'll unlink before execing */
    if (unlink(state_filename)) {
        fprintf(stderr, "Couldn't unlink %s, errno %d\n", state_filename, errno);
    }

    return 0;
}

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

struct readv_info {
    int fd;
    struct iovec* iov;
    int count;
};

struct pread_info {
    int fd;
    void* buf;
    size_t count;
    off_t offset;
};

struct recvmsg_info {
    int fd;
    struct msghdr* msg;
    int flags;
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

/* a structure that describes the opening of a file descriptor
 * e.g. open, pipe, socketpair.
 *
 * Invariant: one of these structs is allocated when the file descriptor is opened/created
 * The same struct is freed when the fd is closed.
 * */
#define MAX_PATH_LEN 256
struct open_info {
    char filename[MAX_PATH_LEN];
    int flags;
    int record_pid;     // record pid that opened this
    int open_syscall_cnt; // syscall that the open occurred
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
    /* Contains information if we end up connecting on
     * this socket
     * NULL if this socket didn't connect somewhere
     * */
    struct connect_info* ci;
    /* If bind is called to a socket, save the info here.
     * Potentially we could, use the ci field since sockets
     * can't connect and bind. But I think it's better to be explicit here.
     * */
    struct connect_info* bind_info;
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
    int sockfd;
    struct sockaddr* addr;
    socklen_t addrlen;
};

struct dup_info {
    int oldfd;
    int newfd;
    int flags;
};

struct gettimeofday_info {
    struct timeval* tv;
};

struct pipe_info {
    int* pipefd;
    int flags;
};

inline
void increment_syscall_cnt (struct thread_data* ptdata, int syscall_num)
{
    // ignore pthread syscalls, or deterministic system calls that we don't log (e.g. 123, 186, 243, 244)
    if (!(syscall_num == 17 || syscall_num == 31 || syscall_num == 32 || syscall_num == 35 || syscall_num == 44 || syscall_num == 53 || syscall_num == 56 || syscall_num == 98 || syscall_num == 119 || syscall_num == 123 || syscall_num == 186 || syscall_num == 243 || syscall_num == 244)) {
        if (ptdata->ignore_flag) {
            if (!(*(int *)(ptdata->ignore_flag))) {
                ptdata->syscall_cnt++;
                global_syscall_cnt++;
            }
        } else {
            global_syscall_cnt++;
            ptdata->syscall_cnt++;
        }
        //global_syscall_cnt++;
    }
}

void make_stream_directory(uint64_t rg_id) 
{
    snprintf(stream_directory, 256, "%s/io_%llu", KnobDirectoryPrefix.Value().c_str(), rg_id);
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
    fprintf(stderr, "Created out file %s\n", filename);
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

		if (fd == 0) {
			fprintf(stderr, "Have stdin\n");
		}

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
                fprintf(stream_fp, "READ from X socket, size: %d\n", rc);
                fflush(stream_fp);
                tdata->bytes_read += rc;
                bytes_read += rc;
            }
        }
#else
        char* channel_name = (char *) "--";
        int rcc;
        int has_fd = 0;
        struct read_info* ri = (struct read_info *) tdata->syscall_info;
				if (ri->fd == 0) {
					fprintf(stderr, "Have stdin\n");
				}
        assert (ri);
        if (monitor_has_fd(open_fds, ri->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, ri->fd);
            assert (oi);
            channel_name = oi->filename;
            fprintf(stream_fp, "%d READ %ld(%ld) size: %d from %s\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, rc, oi->filename);
            fflush(stream_fp);

            has_fd = 1;
        } else if (monitor_has_fd(open_socks, ri->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ri->fd);
            assert (si);
            fprintf(stream_fp, "%d READ %ld(%ld) from socket size: %d\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, rc);
            fflush(stream_fp);
            channel_name = (char *) "socket";

            has_fd = 1;
        } else {
            fprintf(stderr, "untracked read\n");
        }

        if (copy_data && has_fd) {
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
}

void readv_start(int fd, struct iovec* iov, int count)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct readv_info* rvi;
    rvi = (struct readv_info *) malloc(sizeof(struct readv_info));
    rvi->fd = fd;
    rvi->iov = iov;
    rvi->count = count;

    tdata->syscall_info = (void *) rvi;
}

void readv_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct readv_info* rvi = (struct readv_info *) tdata->syscall_info;
    int i;

    if (rc > 0) {
        int has_fd = 0;
        const char* channel_name = (char *) "--";
#ifdef ONLY_X
        if (monitor_has_fd(open_socks, rvi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, rvi->fd);
            if (si->is_x) {
                for (i = 0; i < rvi->count; i++) {
                    struct iovec* vi = (rvi->iov + i);
                    fprintf(stream_fp, "%d READV %ld(%ld) count %d size: %d to X\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, i, vi->iov_len);
                    fflush(stream_fp);
                }
            }
        }
        tdata->bytes_read += rc;
        bytes_read += rc;
#else
        if ((monitor_has_fd(open_fds, rvi->fd))) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, rvi->fd);
            assert (oi);
            for (i = 0; i < rvi->count; i++) {
                struct iovec* vi = (rvi->iov + i);
                fprintf(stream_fp, "%d READV %ld(%ld) count %d size: %d to %s\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, i, vi->iov_len, oi->filename);
            }
            fflush(stream_fp);
            has_fd = 1;
            channel_name = oi->filename;
        } else if (monitor_has_fd(open_socks, rvi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, rvi->fd);
            assert (si);

            for (i = 0; i < rvi->count; i++) {
                struct iovec* vi = (rvi->iov + i);
                fprintf(stream_fp, "%d READV %ld(%ld) count %d size: %d to socket\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, i, vi->iov_len);
            }
            fflush(stream_fp);
            has_fd = 1;
            channel_name = (char *) "SOCKET";
        } else {
            fprintf(stderr, "readv to untracked fd\n");
        }
        tdata->bytes_written += rc;
        bytes_written += rc;
#endif

        if (copy_data && has_fd) {
            unsigned int rcc;
            int offset = 0;
            int out_fd = create_out_file(stream_read_directory, tdata->rg_id, tdata->record_pid, global_syscall_cnt, offset, rc);
            FILE* out_fp = fdopen(out_fd, "w");
            assert (out_fd > 0);
            for (i = 0; i < rvi->count; i++) {
                struct iovec* vi = (rvi->iov + i);
                // write a header
                fprintf(out_fp, "%llu %d %ld %d %d %s\n",
                    tdata->rg_id, tdata->record_pid, global_syscall_cnt, offset, vi->iov_len, channel_name);
                fflush(out_fp);
                rcc = write(out_fd, vi->iov_base, vi->iov_len);
                if (rcc != vi->iov_len) {
                    fprintf(stderr, "readv could not write to mirror file, expected %d got %d, errno %d\n", vi->iov_len, rcc, errno);
                }
                offset += vi->iov_len;
                fsync(out_fd);
            }
            fsync(out_fd);
            close(out_fd);
        }
    }
}

void pread_start(int fd, void* buf, size_t count, off_t offset)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    struct pread_info* pri;
    pri = (struct pread_info *) malloc(sizeof(struct pread_info));

    pri->fd = fd;
    pri->buf = buf;
    pri->count = count;
    pri->offset = offset;

    tdata->syscall_info = (void *) pri;
}

void pread_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    // successful read
    if (rc > 0) {
        char* channel_name = (char *) "--";
        int rcc;
        int has_fd = 0;
        struct pread_info* pri = (struct pread_info *) tdata->syscall_info;
        assert (pri);
        if (monitor_has_fd(open_fds, pri->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, pri->fd);
            assert (oi);
            channel_name = oi->filename;
            fprintf(stream_fp, "%d PREAD %ld(%ld) size: %d (offset %ld) from %s\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, rc, pri->offset, oi->filename);
            fflush(stream_fp);

            has_fd = 1;
        } 

        if (copy_data && has_fd) {
            FILE* out_fp;
            int out_fd = create_out_file(stream_read_directory, tdata->rg_id, tdata->record_pid, global_syscall_cnt, 0, rc);
            assert (out_fd > 0);
            // write a header
            out_fp = fdopen(out_fd, "w");
            assert(out_fp);
            fprintf(out_fp, "%llu %d %ld %d %d %s\n",
                    tdata->rg_id, tdata->record_pid, global_syscall_cnt, 0, rc, channel_name);
            fflush(out_fp);
            rcc = write(out_fd, pri->buf, rc);
            if (rcc != rc) {
                fprintf(stderr, "pread: could not write to read mirror file, expected %d got %d\n", rc, rcc);
            }
            fsync(out_fd);
            close(out_fd);
        }

        tdata->bytes_read += rc;
        bytes_read += rc;

    }
}

void recvmsg_start(int fd, struct msghdr* msg, int flags) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    struct recvmsg_info* rmi;
    rmi = (struct recvmsg_info *) malloc(sizeof(struct recvmsg_info));

    rmi->fd = fd;
    rmi->msg = msg;
    rmi->flags = flags;

    tdata->syscall_info = (void *) rmi;
}

void recvmsg_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct recvmsg_info* rmi = (struct recvmsg_info *) tdata->syscall_info;
    u_int i;

    if (rc > 0) {
        int has_fd = 0;
        const char* channel_name = "--";
#ifdef ONLY_X
        if (monitor_has_fd(open_socks, rmi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, rmi->fd);
            if (si->is_x) {
                for (i = 0; i < rmi->msg->msg_iovlen; i++) {
                    struct iovec* vi = (rmi->msg->msg_iov + i);
                    fprintf(stream_fp, "%d RECVMSG %ld(%ld) count %d size: %d to X\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, i, vi->iov_len);
                    fflush(stream_fp);
                }
            }
        }
        tdata->bytes_read += rc;
        bytes_read += rc;
#else
        if ((monitor_has_fd(open_fds, rmi->fd))) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, rmi->fd);
            assert (oi);
            for (i = 0; i < rmi->msg->msg_iovlen; i++) {
                struct iovec* vi = (rmi->msg->msg_iov + i);
                fprintf(stream_fp, "%d RECVMSG %ld(%ld) count %d size: %d to %s\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, i, vi->iov_len, oi->filename);
            }
            fflush(stream_fp);
            has_fd = 1;
            channel_name = oi->filename;
        } else if (monitor_has_fd(open_socks, rmi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, rmi->fd);
            assert (si);

            for (i = 0; i < rmi->msg->msg_iovlen; i++) {
                struct iovec* vi = (rmi->msg->msg_iov + i);
                fprintf(stream_fp, "%d RECVMSG %ld(%ld) count %d size: %d to socket\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, i, vi->iov_len);
            }
            fflush(stream_fp);
            has_fd = 1;
            channel_name = (char *) "SOCKET";
        } else {
            fprintf(stderr, "rcvmsg to untracked fd\n");
        }
        tdata->bytes_written += rc;
        bytes_written += rc;
#endif

        if (copy_data && has_fd) {
            int offset = 0;
            int out_fd = create_out_file(stream_read_directory, tdata->rg_id, tdata->record_pid, global_syscall_cnt, offset, rc);
            FILE* out_fp = fdopen(out_fd, "w");
            assert (out_fd > 0);
            for (i = 0; i < rmi->msg->msg_iovlen; i++) {
                unsigned int rcc;
                struct iovec* vi = (rmi->msg->msg_iov + i);
                // write a header
                fprintf(out_fp, "%llu %d %ld %d %d %s\n",
                    tdata->rg_id, tdata->record_pid, SYSCALL_CNT, offset, vi->iov_len, channel_name);
                fflush(out_fp);
                rcc = write(out_fd, vi->iov_base, vi->iov_len);
                if (rcc != vi->iov_len) {
                    fprintf(stderr, "recvmsg could not write to mirror file, expected %d got %d\n", rc, rcc);
                }
                offset += vi->iov_len;
                fsync(out_fd);
            }
            fsync(out_fd);
            close(out_fd);
        }
    }
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
                fprintf(stream_fp, "WRITE TO X socket, size: %d, %s\n", rc, channel_name);
                fflush(stream_fp);
                tdata->bytes_written += rc;
                bytes_written += rc;
            }
        }
#else
        int has_fd = 0;
        struct write_info* wi = (struct write_info *) tdata->syscall_info;
        int rcc;
        char buf[rc];
        snprintf(buf, rc, "%s", (char *) wi->buf);
        fprintf(stderr, "write_stop %s\n", buf);
        if (monitor_has_fd(open_fds, wi->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, wi->fd);
            assert(oi);
            channel_name = oi->filename;
            fprintf(stream_fp, "%d WRITE %ld(%ld) size: %d to %s\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, rc, oi->filename);
            fflush(stream_fp);
            has_fd = 1;
        } else if (monitor_has_fd(open_socks, wi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, wi->fd);
            assert(si);
            if (si->accept_info) {
                char channel_name[256];
                if (si->domain == AF_UNIX) {
                    // XXX Do we need to use the magic number here instead? There are weird path names with \0 in it
                    snprintf(channel_name, 256, "%s", si->accept_info->path);
                } else if (si->domain == AF_INET) {
                    int port;
                    char straddr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &si->ci->sin_addr, straddr, INET_ADDRSTRLEN);
                    port = si->ci->port;
                    snprintf(channel_name, 256, "(accept)%s:%d", straddr, port);
                } else if (si->domain == AF_INET6) {
                    int port;
                    char straddr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &si->ci->sin_addr6, straddr, INET_ADDRSTRLEN);
                    port = si->ci->port;
                    snprintf(channel_name, 256, "(accept)%s:%d", straddr, port);
                } else {
                    snprintf(channel_name, 256, "%s", "unknown_accepted_socket");
                }
                fprintf(stream_fp, "%d WRITE %ld(%ld) to socket size: %d %s\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, rc, channel_name);
            } else if (si->ci) {
                char channel_name[256];
                if (si->domain == AF_UNIX) {
                    // XXX Do we need to use the magic number here instead? There are weird path names with \0 in it
                    snprintf(channel_name, 256, "%s", si->ci->path);
                } else if (si->domain == AF_INET) {
                    int port;
                    char straddr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &si->ci->sin_addr, straddr, INET_ADDRSTRLEN);
                    port = si->ci->port;
                    snprintf(channel_name, 256, "%s:%d", straddr, port);
                } else if (si->domain == AF_INET6) {
                    int port;
                    char straddr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &si->ci->sin_addr6, straddr, INET_ADDRSTRLEN);
                    port = si->ci->port;
                    snprintf(channel_name, 256, "%s:%d", straddr, port);
                } else {
                    snprintf(channel_name, 256, "%s", "unknown_socket");
                }
                fprintf(stream_fp, "%d WRITE %ld(%ld) to connected socket size: %d %s\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, rc, channel_name);
            } else {
                fprintf(stream_fp, "%d WRITE %ld(%ld) to socket size: %d\n", tdata->record_pid, global_syscall_cnt, SYSCALL_CNT, rc);
                if (si->domain == AF_UNIX) {
                    channel_name = si->ci->path;
                } else if (si->domain == AF_INET) {
                    // TODO
                } else if (si->domain == AF_INET6) {
                    // TODO
                }
            }
            fflush(stream_fp);
            has_fd = 1;
        } else {
            fprintf(stderr, "write to untracked fd\n");
        }

        if (copy_data && has_fd) {
            FILE* out_fp;
            int out_fd = create_out_file(stream_write_directory, tdata->rg_id, tdata->record_pid, SYSCALL_CNT, 0, rc);
            assert (out_fd > 0);
            // write a header
            out_fp = fdopen(out_fd, "w");
            fprintf(out_fp, "%llu %d %ld %d %d %s\n",
                    tdata->rg_id, tdata->record_pid, SYSCALL_CNT, 0, rc, channel_name);
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
        int has_fd = 0;
        const char* channel_name = (char *) "--";
#ifdef ONLY_X
        if (monitor_has_fd(open_socks, wvi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, wvi->fd);
            if (si->is_x) {
                for (i = 0; i < wvi->count; i++) {
                    struct iovec* vi = (wvi->iov + i);
                    fprintf(stream_fp, "WRITEV %ld count %d size: %d to X\n", global_syscall_cnt, i, vi->iov_len);
                    fflush(stream_fp);
                }
            }
        }
        tdata->bytes_written += rc;
        bytes_written += rc;
#else
        if ((monitor_has_fd(open_fds, wvi->fd))) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, wvi->fd);
            assert (oi);
            for (i = 0; i < wvi->count; i++) {
                struct iovec* vi = (wvi->iov + i);
                fprintf(stream_fp, "WRITEV %ld count %d size: %d to %s\n", global_syscall_cnt, i, vi->iov_len, oi->filename);
            }
            has_fd = 1;
            channel_name = oi->filename;
        } else if (monitor_has_fd(open_socks, wvi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, wvi->fd);
            assert (si);

            for (i = 0; i < wvi->count; i++) {
                struct iovec* vi = (wvi->iov + i);
                fprintf(stream_fp, "WRITEV %ld count %d size: %d to socket\n", global_syscall_cnt, i, vi->iov_len);
            }
            fflush(stream_fp);
            has_fd = 1;
            channel_name = (char *) "SOCKET";
        } else {
            fprintf(stderr, "writev to untracked fd\n");
        }
        tdata->bytes_written += rc;
        bytes_written += rc;
#endif

        if (copy_data && has_fd) {
            int offset = 0;
            int out_fd = create_out_file(stream_write_directory, tdata->rg_id, tdata->record_pid, SYSCALL_CNT, 0, rc);
            FILE* out_fp = fdopen(out_fd, "w");
            assert (out_fd > 0);
            for (i = 0; i < wvi->count; i++) {
                unsigned int rcc;
                struct iovec* vi = (wvi->iov + i);
                if (vi->iov_len) {
                    // write a header
                    fprintf(out_fp, "%llu %d %ld %d %d %s\n",
                            tdata->rg_id, tdata->record_pid, global_syscall_cnt, offset, vi->iov_len, channel_name);
                    fflush(out_fp);
                    rcc = write(out_fd, vi->iov_base, vi->iov_len);
                    if (rcc != vi->iov_len) {
                        fprintf(stderr, "writev could not write to mirror file, expected %d got %d\n", vi->iov_len, rcc);
                    }
                    offset += vi->iov_len;
                }
                fsync(out_fd);
            }
            fsync(out_fd);
            close(out_fd);
        }
    }
}

void open_start(char* filename, int flags) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct open_info* oi;
    oi = (struct open_info *) malloc(sizeof(struct open_info));
    memset(oi, 0, sizeof(struct open_info));
    DEBUG_PRINT(stderr, "[OPEN] open_start, filename is %s, len %d\n", filename, strlen(filename));
    strncpy(oi->filename, filename, MAX_PATH_LEN);
    oi->flags = flags;
    oi->open_syscall_cnt = global_syscall_cnt;
    oi->record_pid = tdata->record_pid;

    tdata->syscall_info = (void *) oi;
}

void open_stop(int rc) {
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct open_info* oi = (struct open_info *) tdata->syscall_info;
    // on successful open
    if (rc > 0) {
        int cloexec = 0;
        cloexec = oi->flags & O_CLOEXEC;
        DEBUG_PRINT (stderr, "[OPEN] Successful open of %s, fd %d, cloexec 0x%x\n", oi->filename, rc, cloexec);
        fprintf (stream_fp, "OPEN %ld %s, fd %d, cloexec 0x%x\n", global_syscall_cnt, oi->filename, rc, cloexec);
        DEBUG_PRINT(stderr, "open_fds has %d fds\n", monitor_size(open_fds));
        monitor_add_fd(open_fds, rc, cloexec, oi);
        tdata->syscall_info = NULL; // monitor owns oi now

        fprintf(filenames, "%ld %s\n", global_syscall_cnt, oi->filename);
        fflush(filenames);
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
        DEBUG_PRINT (stderr, "[CLOSE] Successful close of %d\n", ci->fd);
        if (monitor_has_fd(open_fds, ci->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, ci->fd);
            assert (oi);
            DEBUG_PRINT(stderr, "[CLOSE] of file %s\n", oi->filename);
            free(oi);
            monitor_remove_fd(open_fds, ci->fd);
            DEBUG_PRINT(stderr, "open_fds has %d fds\n", monitor_size(open_fds));
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
        assert (mi);

        if (!include_mmap_exec && (mi->prot & PROT_EXEC)) {
            // Before returning, count these are bytes read
            tdata->bytes_read += mi->length;
            bytes_read += mi->length;
            // mi will be freed after syscall
            return;
        }

        if (monitor_has_fd(open_fds, mi->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, mi->fd);
            assert (oi);
            fprintf(stream_fp, "MMAP %ld size: %d from %s\n", global_syscall_cnt, mi->length, oi->filename);
            fflush(stream_fp);

            if (copy_data) {
                FILE* out_fp;
                int out_fd;
                out_fd = create_out_file(stream_read_directory, tdata->rg_id, tdata->record_pid, SYSCALL_CNT, 0, mi->length);
                assert (out_fd > 0);
                // write a header
                out_fp = fdopen(out_fd, "w");
                assert(out_fp);
                fprintf(out_fp, "%llu %d %ld %d %d %s\n",
                        tdata->rg_id, tdata->record_pid, global_syscall_cnt, 0, mi->length, oi->filename);
                fflush(out_fp);
                rcc = write(out_fd, rc, mi->length);
                if (rcc != mi->length) {
                    fprintf(stderr, "could not write to read mirror file, expected %d got %d\n", mi->length, rcc);
                }
                fsync(out_fd);
                close(out_fd);
            }

            tdata->bytes_read += mi->length;
            bytes_read += mi->length;
        } else if (mi->fd != -1) {
            fprintf(stderr, "untracked mmap, fd %d\n", mi->fd);
        }
    }
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
        tdata->syscall_info = NULL; // Giving si to the monitor
    }
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
            if (addr->sa_family == AF_INET || addrlen == sizeof(struct sockaddr_in)) {
                struct sockaddr_in* sin = (struct sockaddr_in*) addr;
                ci->port = htons(sin->sin_port);
                memcpy(&ci->sin_addr, &sin->sin_addr, sizeof(struct in_addr));
                fprintf (stderr, "connect AF_INET port %d addr %x\n", ci->port, ci->sin_addr.s_addr);
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
        if (!si) {
            fprintf(stderr, "could not find socket info for connect, fd is %d\n", ci->fd);
            return;
        }

        si->ci = ci;
        tdata->syscall_info = NULL; // Socket_info owns this now
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
            fprintf(stream_fp, "CONNECT %ld AF_UNIX path %s\n", global_syscall_cnt, ci->path);
            fflush(stream_fp);
        } else if (si->domain == AF_INET) {
            char straddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ci->sin_addr, straddr, INET_ADDRSTRLEN);
            fprintf(stream_fp, "CONNECT %ld AF_INET addr: %s port %d\n", global_syscall_cnt, straddr, ci->port);
            fflush(stream_fp);
        } else if (si->domain == AF_INET6) {
            char straddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ci->sin_addr6, straddr, INET6_ADDRSTRLEN);
            fprintf(stream_fp, "CONNECT %ld AF_INET6 addr: %s port %d\n", global_syscall_cnt, straddr, ci->port);
            fflush(stream_fp);
        } else {
            fprintf(stream_fp, "CONNECT %ld domain: %d\n", global_syscall_cnt, si->domain);
            fflush(stream_fp);
        }
#endif
    }
}

void bind_start(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (monitor_has_fd(open_socks, sockfd)) {
        struct socket_info* si = (struct socket_info*) monitor_get_fd_data(open_socks, sockfd);
        /* bind has all of the same fields as collect, so just use the collect struct */
        struct connect_info* bi = (struct connect_info *) malloc(sizeof(struct connect_info));
        memset(bi, 0, sizeof(struct connect_info));
        assert(si);

        bi->fd = sockfd;
        if (si->domain == AF_UNIX) {
            struct sockaddr_un* sun = (struct sockaddr_un*) addr;
            if (addr->sa_family == AF_UNIX) {
                memcpy(bi->path, sun->sun_path, 108); // apparently 108 is the magic number
            } else {
                fprintf (stderr, "bind: unknown sa_family %d is not AF_UNIX len is %d vs %d\n",
                        addr->sa_family, addrlen, sizeof(struct sockaddr_un));
                memcpy(bi->path, "UNK", 4);
            }
        } else if (si->domain == AF_INET) {
            if (addr->sa_family == AF_INET || addrlen == sizeof(struct sockaddr_in)) {
                struct sockaddr_in* sin = (struct sockaddr_in*) addr;
                bi->port = htons(sin->sin_port);
                memcpy(&bi->sin_addr, &sin->sin_addr, sizeof(struct in_addr));
                fprintf (stderr, "bind AF_INET port %d addr %x\n", bi->port, bi->sin_addr.s_addr);
            } else {
                fprintf (stderr, "bind: unknown sa_family %d is not AF_INET len is %d vs %d\n",
                        addr->sa_family, addrlen, sizeof(struct sockaddr_in));
                bi->port = 0;
                memcpy(&bi->sin_addr, "UNK", 4);
            }
        } else if (si->domain == AF_INET6) {
            if (addr->sa_family == AF_INET6) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*) addr;
                bi->port = htons(sin6->sin6_port);
                memcpy(&bi->sin_addr6, &sin6->sin6_addr, sizeof(struct in6_addr));
            } else {
                fprintf (stderr, "bind: unknown sa_family %d is not AF_INET6 len is %d vs %d\n",
                        addr->sa_family, addrlen, sizeof(struct sockaddr_in6));
                bi->port = 0;
                memcpy(&bi->sin_addr6, "UNK", 4);
            }
        } else {
            fprintf(stderr, "bind: unsupport socket family %d\n", si->domain);
            free(bi);
            return;
        }
        tdata->syscall_info = (void *) bi;
    }
}

void bind_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    // successful bind
    if (!rc && tdata->syscall_info) {
        struct connect_info* bi = (struct connect_info *) tdata->syscall_info;
        struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, bi->fd);
        if (!si) {
            fprintf(stderr, "could not find socket info for bind, fd is %d\n", bi->fd);
            return;
        }

        si->bind_info = bi;
        tdata->syscall_info = NULL; // Socket_info owns this now
        
        // output to stream_fp
        if (si->domain == AF_UNIX) {
            fprintf(stream_fp, "BIND %ld AF_UNIX path %s\n", global_syscall_cnt, bi->path);
            fprintf(stderr, "bind on fd %d\n", bi->fd);
            fflush(stream_fp);
        } else if (si->domain == AF_INET) {
            char straddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &bi->sin_addr, straddr, INET_ADDRSTRLEN);
            fprintf(stream_fp, "BIND %ld AF_INET addr: %s port %d\n", global_syscall_cnt, straddr, bi->port);
            fflush(stream_fp);
        } else if (si->domain == AF_INET6) {
            char straddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &bi->sin_addr6, straddr, INET6_ADDRSTRLEN);
            fprintf(stream_fp, "BIND %ld AF_INET6 addr: %s port %d\n", global_syscall_cnt, straddr, bi->port);
            fflush(stream_fp);
        }
    }
}

void accept_start(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    fprintf(stderr, "accept start on fd %d\n", sockfd);
    if (monitor_has_fd(open_socks, sockfd)) {
        struct accept_info* ai = (struct accept_info *) malloc(sizeof(struct accept_info));
        /* The bound socket we're listening on*/
        struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, sockfd);
        assert (si);

        ai->sockfd = sockfd;
        ai->addr = addr;
        ai->addrlen = addrlen;
        tdata->syscall_info = (void *) ai;
    }
}

void accept_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    // successful accept
    if (rc > 0 && tdata->syscall_info) {
        /* On a successful accept, we create a new socket for the accepted socket.
         * With that socket info, we keep the associated connect and accept metadata.
         * */
        struct accept_info* ai = (struct accept_info *) tdata->syscall_info;
        /* Describes the socket returned by accept */
        struct socket_info* si = (struct socket_info *) malloc(sizeof(struct socket_info));
        struct connect_info* accept_ci = (struct connect_info *) malloc(sizeof(struct connect_info));
        /* Describes the accepting socket */
        struct socket_info* accept_si = (struct socket_info *) monitor_get_fd_data(open_socks, ai->sockfd);
        struct connect_info* accepting_ci = (struct connect_info *) malloc(sizeof(struct connect_info));
        assert(accept_si);
        memset(accepting_ci, 0, sizeof(struct connect_info));

        si->call = SYS_ACCEPT;
        si->domain = accept_si->domain;
        si->type = accept_si->type;
        si->protocol = accept_si->protocol;

        /* Save information about the accepting socket to the accepted socket */
        memcpy(accepting_ci, accept_si->bind_info, sizeof(struct connect_info));
        si->accept_info = accepting_ci;

        // populate the connect info
        if (accept_si->domain == AF_UNIX) {
            struct sockaddr_un* sun = (struct sockaddr_un*) ai->addr;
            if (ai->addr->sa_family == AF_UNIX) {
                memcpy(accept_ci->path, sun->sun_path, 108); // apparently 108 is the magic number
            } else {
                fprintf (stderr, "accept: unknown sa_family %d is not AF_UNIX len is %d vs %d\n",
                        ai->addr->sa_family, ai->addrlen, sizeof(struct sockaddr_un));
                memcpy(accept_ci->path, "UNK", 4);
            }
        } else if (accept_si->domain == AF_INET) {
            if (ai->addr->sa_family == AF_INET || ai->addrlen == sizeof(struct sockaddr_in)) {
                struct sockaddr_in* sin = (struct sockaddr_in*) ai->addr;
                accept_ci->port = htons(sin->sin_port);
                memcpy(&accept_ci->sin_addr, &sin->sin_addr, sizeof(struct in_addr));
                fprintf (stderr, "connect AF_INET port %d addr %x\n",
                        accept_ci->port, accept_ci->sin_addr.s_addr);
            } else {
                fprintf (stderr, "unknown sa_family %d is not AF_INET len is %d vs %d\n",
                        ai->addr->sa_family, ai->addrlen, sizeof(struct sockaddr_in));
                accept_ci->port = 0;
                memcpy(&accept_ci->sin_addr, "UNK", 4);
            }
        } else if (accept_si->domain == AF_INET6) {
            if (ai->addr->sa_family == AF_INET6 || ai->addrlen == sizeof(struct sockaddr_in6)) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*) ai->addr;
                accept_ci->port = htons(sin6->sin6_port);
                memcpy(&accept_ci->sin_addr6, &sin6->sin6_addr, sizeof(struct in6_addr));
            } else {
                fprintf (stderr, "unknown sa_family %d is not AF_INET6 len is %d vs %d\n",
                        ai->addr->sa_family, ai->addrlen, sizeof(struct sockaddr_in6));
                accept_ci->port = 0;
                memcpy(&accept_ci->sin_addr6, "UNK", 4);
            }
        }
        si->ci = accept_ci;

        // add the returned socket to the open_socks
        monitor_add_fd(open_socks, rc, 0, si);
        tdata->syscall_info = NULL; // monitor owns si now

        if (accept_si->domain == AF_INET) {
            int port;
            int connect_port;
            char straddr[INET_ADDRSTRLEN];
            char connect_straddr[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &accepting_ci->sin_addr, straddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &accept_ci->sin_addr, connect_straddr, INET_ADDRSTRLEN);
            port = accepting_ci->port;
            connect_port = accept_ci->port;
            fprintf(stream_fp, "ACCEPTed %ld AF_INET on %s port %d from %s on port %d\n",
                    global_syscall_cnt, straddr, port, connect_straddr, connect_port);
        } else if (accept_si->domain == AF_INET6) {
            int port;
            int connect_port;
            char straddr[INET_ADDRSTRLEN];
            char connect_straddr[INET_ADDRSTRLEN];

            inet_ntop(AF_INET6, &accepting_ci->sin_addr6, straddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET6, &accept_ci->sin_addr6, connect_straddr, INET_ADDRSTRLEN);
            port = accepting_ci->port;
            connect_port = accept_ci->port;
            fprintf(stream_fp, "ACCEPTed %ld AF_INET6 on %s port %d from %s on port %d\n",
                    global_syscall_cnt, straddr, port, connect_straddr, connect_port);
        } else if (accept_si->domain == AF_UNIX) {
            fprintf(stream_fp, "ACCEPTed %ld AF_UNIX\n", global_syscall_cnt);
            // TODO
        } else {
            fprintf(stream_fp, "ACCEPT %ld unknown domain\n", global_syscall_cnt);
        }
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
        fprintf (stderr, "[DUP] dup returns %d, oldfd %d\n", rc, di->oldfd);
        if (monitor_has_fd(open_fds, di->oldfd)) {
        }
    }
}

void gettimeofday_start(struct timeval* tv)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct gettimeofday_info* gi;
    gi = (struct gettimeofday_info *) malloc(sizeof(struct gettimeofday_info));
    gi->tv = tv;

    tdata->syscall_info = (void *) gi;
}

void gettimeofday_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct gettimeofday_info* gi;
    gi = (struct gettimeofday_info *) tdata->syscall_info;

    if (!rc) { // successful
        fprintf(times_fp, "%ld %ld\n", global_syscall_cnt, gi->tv->tv_sec);
        fflush(times_fp);
    }
}

void pipe_start(int* pipefd, int flags)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct pipe_info* pi = (struct pipe_info *) malloc(sizeof(struct pipe_info));
    pi->pipefd = pipefd;
    pi->flags = flags;

    tdata->syscall_info = (void *) pi;
}

void pipe_stop(int rc)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct pipe_info* pi = (struct pipe_info *) tdata->syscall_info;

    if (!rc) { // successful
        int cloexec = 0;
        struct open_info* read_oi;
        struct open_info* write_oi;

        cloexec = pi->flags & O_CLOEXEC;

        // read fd
        read_oi = (struct open_info *) malloc(sizeof(struct open_info));
        snprintf(read_oi->filename, MAX_PATH_LEN, "PIPE(R)@%ld", global_syscall_cnt);
        read_oi->flags = pi->flags;
        read_oi->record_pid = tdata->record_pid;
        read_oi->open_syscall_cnt = global_syscall_cnt;
        monitor_add_fd(open_fds, pi->pipefd[0], cloexec, read_oi);

        // write fd
        write_oi = (struct open_info *) malloc(sizeof(struct open_info));
        snprintf(write_oi->filename, MAX_PATH_LEN, "PIPE(W)@%ld", global_syscall_cnt);
        write_oi->flags = pi->flags;
        write_oi->record_pid = tdata->record_pid;
        write_oi->open_syscall_cnt = global_syscall_cnt;
        monitor_add_fd(open_fds, pi->pipefd[0], cloexec, write_oi);
    }
}

void instrument_syscall_ret(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
        if (tdata->app_syscall != 999) tdata->app_syscall = 0;
    } else {
        fprintf (stderr, "instrument_syscall_ret: NULL tdata\n");
    }
    fprintf (stderr, "%ld Pid %d, tid %d, (record pid %d), %ld: syscall ret is %d\n", global_syscall_cnt, PIN_GetPid(), PIN_GetTid(), tdata->record_pid, tdata->syscall_cnt, tdata->sysnum);
    ADDRINT ret_value = PIN_GetSyscallReturn(ctxt, std);

    switch (tdata->sysnum) {
        case SYS_open:
            open_stop((int) ret_value);
            break;
        case SYS_close:
            close_stop((int) ret_value);
            break;
        case SYS_mmap2:
            mmap_stop((void *) ret_value);
            break;
        case SYS_read:
            read_stop((int) ret_value);
            break;
        case SYS_write:
            write_stop((int) ret_value);
            break;
        case SYS_readv:
            readv_stop((int) ret_value);
            break;
        case SYS_writev:
            writev_stop((int) ret_value);
            break;
        case SYS_pread64:
            pread_stop((int) ret_value);    
        case SYS_dup:
            dup_stop((int) ret_value);
            break;
        case SYS_dup3:
            break;
        case SYS_dup2:
            break;
        case SYS_fcntl:
            break;
        case SYS_gettimeofday:
            gettimeofday_stop((int) ret_value);
            break;
        case SYS_pipe:
            pipe_stop((int) ret_value);
            break;
        case SYS_pipe2:
            pipe_stop((int) ret_value);
            break;
        case SYS_socketcall:
            int call = tdata->socketcall;
            fprintf(stderr, " making socketcall %d\n", call);
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
                case SYS_RECVMSG:
                    recvmsg_stop((int) ret_value);
                    break;
                case SYS_BIND:
                    // TODO
                    bind_stop((int) ret_value);
                    break;
                case SYS_ACCEPT:
                case SYS_ACCEPT4:
                    // TODO
                    accept_stop((int) ret_value);
                    break;
                case SYS_SOCKETPAIR:
                    // TODO: Just like Pipe
                default:
                    fprintf(stderr, "Unknown socket call %d\n", call);
            }
            break;
    }

    increment_syscall_cnt(tdata, tdata->sysnum);
    // reset the syscall number after returning from system call
    if (tdata->syscall_info) free (tdata->syscall_info);
    tdata->sysnum = 0;
    tdata->socketcall = 0;
}

// called before every application system call
void instrument_syscall(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2, ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{   
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
        int sysnum = (int) syscall_num;

        fprintf (stderr, "%ld Pid %d, tid %d, (record pid %d), %ld: syscall num is %d\n", global_syscall_cnt, PIN_GetPid(), PIN_GetTid(), tdata->record_pid, tdata->syscall_cnt, (int) syscall_num);

        if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
            check_clock_before_syscall (dev_fd, (int) syscall_num);
        }
        tdata->sysnum = syscall_num;
	tdata->syscall_info = NULL;

        switch(sysnum) {
        case 31:
            tdata->ignore_flag = (u_long) syscallarg1;
            break;
        case SYS_execve:
        {
            char* program_name = (char *) syscallarg0;
            fprintf(stderr, "Trying to exec %s\n", program_name);
	    // need to increment here because exec does not return
	    increment_syscall_cnt(tdata, sysnum);
            break;
        }
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
        case SYS_read:
            read_start((int)syscallarg0, (void *)syscallarg1, (int)syscallarg2);
            break;
        case SYS_readv:
            readv_start((int)syscallarg0, (struct iovec*)syscallarg1, (int)syscallarg2);
            break;
        case SYS_pread64:
            pread_start((int)syscallarg0, (void *)syscallarg1, (size_t)syscallarg2, (off_t) syscallarg3);
        case SYS_write:
            write_start((int)syscallarg0, (void *)syscallarg1, (int)syscallarg2);
            break;
        case SYS_writev:
            writev_start((int)syscallarg0, (struct iovec*)syscallarg1, (int)syscallarg2);
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
        case SYS_gettimeofday:
            gettimeofday_start((struct timeval *)syscallarg0);
            break;
        case SYS_pipe:
            pipe_start((int *)syscallarg0, 0);
            break;
        case SYS_pipe2:
            pipe_start((int *)syscallarg0, (int) syscallarg1);
            break;
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
                case SYS_RECVMSG:
                    recvmsg_start ((int)args[0], (struct msghdr *)args[1], (int)args[2]);
                    break;
                case SYS_SOCKETPAIR:
                    break;
                case SYS_BIND:
                    // TODO
                    bind_start((int)args[0], (struct sockaddr *)args[1], (socklen_t)args[2]);
                    break;
                case SYS_ACCEPT:
                case SYS_ACCEPT4:
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

    // reset syscall index for thread
    tdata->syscall_cnt = 0;
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

void change_getpid(ADDRINT reg_ref)
{
    int pid = get_record_pid();
    *(int*)reg_ref = pid;
}

void routine (RTN rtn, VOID *v)
{
    const char *name;

    name = RTN_Name(rtn).c_str();

    RTN_Open(rtn);

    /* 
     * On replay we can't return the replayed pid from the kernel because Pin
     * needs the real pid too. (see kernel/replay.c replay_clone).
     * To account for glibc caching of the pid, we have to account for the 
     * replay pid in the pintool itself.
     * */
    if (!strcmp(name, "getpid") || !strcmp(name, "__getpid")) {
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)change_getpid, 
                IARG_REG_REFERENCE, LEVEL_BASE::REG_EAX, IARG_END);
    }

    RTN_Close(rtn);
}

BOOL follow_child(CHILD_PROCESS child, void* data)
{
    // TODO: persist fd struct over an exec
    char** argv;
    char** prev_argv = (char**)data;
    int index = 0;
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

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

    fprintf(stderr, "Save state before exec-ing\n");
    save_state_to_disk(tdata);

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
        stream_fp = fopen(stream_filename, "w");

        if (!filenames) {
            char filename_file[256];
            snprintf(filename_file, 256, "%s/filenames", stream_directory);
            filenames = fopen(filename_file, "w");
            if (!filenames) {
                fprintf(stderr, "Could not create %s/filenames\n", stream_directory);
                exit(0);
            }
        }

        if (!times_fp) {
            char times_filename[256];
            snprintf(times_filename, 256, "%s/times", stream_directory);
            times_fp = fopen(times_filename, "w");
            if (!times_fp) {
                fprintf(stderr, "Could not create %s/times\n", stream_directory);
                exit(0);
            }
        }

        first_thread = 0;
    }

    if (child) {
        if (restore_state_from_disk(ptdata)) {
            fprintf(stderr, "WARN -- problem restoring state after exec\n");
        }
        fprintf(stderr, "Restored state, global syscall cnt is %ld\n", global_syscall_cnt);
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

    if (!strcmp(argv[4], "--")) { // pin injected into forked process
        child = 1;
    } else { // pin attached to replay process
        child = 0;
    }

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "ERROR: could not initialize Pin?\n");
        exit(-1);
    }

    // check to make sure the directory you provided exists
    DIR* dir_f = opendir(KnobDirectoryPrefix.Value().c_str());
    if (!dir_f) {
        fprintf(stderr, "Could not open directory %s, errno %d\n", KnobDirectoryPrefix.Value().c_str(), errno);
        exit(-1);
    }
    closedir(dir_f);

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
    RTN_AddInstrumentFunction (routine, 0);

    PIN_AddSyscallExitFunction(instrument_syscall_ret, 0);
    PIN_StartProgram();

    return 0;
}
