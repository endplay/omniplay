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

#include <sys/wait.h>
#include <signal.h>

#include "xray_monitor.h"

long global_syscall_cnt = 0;

struct thread_data {
    u_long app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    int record_pid; 	// per thread record pid
    int syscall_cnt;	// per thread count of syscalls
    int sysnum;		// current syscall number
    int socketcall;	// current socketcall num if applicable
    u_long ignore_flag;
    void* syscall_info;
};

ADDRINT array[10000];
int child = 0;

int fd; // File descriptor for the replay device
TLS_KEY tls_key; // Key for accessing TLS. 

// mcc: the xray_monitor structure is just a wrapper around a 
//   linked list of file decriptors. If it turns out that there
//   are so many open fds, it might be more performant to 
//   change this to a hashtable.

/* List of open files*/
struct xray_monitor* open_fds = NULL;

/* List of open sockets */
struct xray_monitor* open_socks = NULL;

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

#define MAX_PATH_LEN 256
struct open_info {
    char filename[MAX_PATH_LEN];
    FILE* fp;
    int flags;
};

struct close_info {
    int fd;
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
    FILE* fp;
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

inline
void increment_syscall_cnt (struct thread_data* ptdata, int syscall_num)
{
    // ignore pthread syscalls, or deterministic system calls that we don't log (e.g. 243, 244)
    if (!(syscall_num == 17 || syscall_num == 31 || syscall_num == 32 || syscall_num == 35 || syscall_num == 44 || syscall_num == 53 || syscall_num == 56 || syscall_num == 98 || syscall_num == 243 || syscall_num == 244)) {
        if (ptdata->ignore_flag) {
            if (!(*(int *)(ptdata->ignore_flag))) {
                ptdata->syscall_cnt++;
                global_syscall_cnt++;
            }
        } else {
            global_syscall_cnt++;
            ptdata->syscall_cnt++;
        }
    }
    global_syscall_cnt++;
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
        int rcc;
        struct read_info* ri = (struct read_info *) tdata->syscall_info;
        FILE* fp = NULL;
        assert (ri);
        if (monitor_has_fd(open_fds, ri->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, ri->fd);
            assert (oi);
            fprintf(stderr, "read from file %s\n", oi->filename);
            fprintf(meta_fp, "READ %ld size: %d from %s\n", global_syscall_cnt, rc, oi->filename);
            fflush(meta_fp);
        } else if (monitor_has_fd(open_socks, ri->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ri->fd);
            assert (si);
            fprintf(meta_fp, "READ from socket %ld size: %d\n", global_syscall_cnt, rc);
            fflush(meta_fp);
        } else {
            fprintf(stderr, "untracked read\n");
        }

        if (fp) {
            rcc = write(fileno(fp), ri->buf, rc);
            if (rcc != rc) {
                fprintf(stderr, "could not write %d bytes\n", rcc);
            }
            fflush(fp);
        }
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
        struct write_info* wi = (struct write_info *) tdata->syscall_info;
        int rcc;
        FILE* fp = NULL;
        if (monitor_has_fd(open_fds, wi->fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, wi->fd);
            assert(oi);
            fprintf(stderr, "write to file %s", oi->filename);
            fp = oi->fp;
            fprintf(meta_fp, "WRITE %ld size: %d from %s\n", global_syscall_cnt, rc, oi->filename);
            fflush(meta_fp);
        } else if (monitor_has_fd(open_socks, wi->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, wi->fd);
            assert(si);
	    fprintf(stderr, "write to socket %d\n", wi->fd);
            fp = si->fp;
            if (si->accept_info) {
                fprintf(meta_fp, "WRITE to socket %ld size: %d (accepted socket)\n", global_syscall_cnt, rc);
            } else {
                fprintf(meta_fp, "WRITE to socket %ld size: %d\n", global_syscall_cnt, rc);
            }
            fflush(meta_fp);
        } else {
            fprintf(stderr, "untracked write\n");
        }

        // write out contents of buffer
        if (fp) {
            rcc = write(fileno(fp), wi->buf, rc);
            if (rcc != rc) {
                fprintf(stderr, "could not write %d bytes\n", rcc);
            }
            fflush(fp);
        }
    }

    free(tdata->syscall_info);
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
        char stream_name[256];
        // Make the stream filename start with the global syscall cnt
        snprintf(stream_name, 256, "/tmp/io_%ld", global_syscall_cnt);
        oi->fp = fopen(stream_name, "w");

        cloexec = oi->flags | O_CLOEXEC;
        fprintf(stderr, "Open add fd %d, cloexec %d\n", rc, cloexec);
        monitor_add_fd(open_fds, rc, cloexec, oi);
        tdata->syscall_info = 0;
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
            fflush(oi->fp);
            fclose(oi->fp);

            free(oi);
            monitor_remove_fd(open_fds, ci->fd);
        } else if (monitor_has_fd(open_socks, ci->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ci->fd);
            assert (si);
            fflush(si->fp);
            fclose(si->fp);

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
            assert(addr->sa_family == AF_UNIX);
            strncpy(ci->path, sun->sun_path, MAX_PATH_LEN);
	    fprintf(stderr, "connect path is %s\n", ci->path);
        } else if (si->domain == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*) addr;
            assert(addr->sa_family == AF_INET);
            ci->port = htons(sin->sin_port);
            memcpy(&ci->sin_addr, &sin->sin_addr, sizeof(struct in_addr));
        } else if (si->domain == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*) addr;
            assert(addr->sa_family == AF_INET6);
            ci->port = htons(sin6->sin6_port);
            memcpy(&ci->sin_addr6, &sin6->sin6_addr, sizeof(struct in6_addr));
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
        char stream_name[256];
        struct connect_info* ci = (struct connect_info *) tdata->syscall_info;
        struct socket_info* si = (struct socket_info*) monitor_get_fd_data(open_socks, ci->fd);
        assert(si);

        si->ci = ci;
        tdata->syscall_info = 0;

        if (si->domain == AF_UNIX) {
            fprintf(meta_fp, "CONNECT %ld AF_UNIX path %s\n", global_syscall_cnt, ci->path);
            fflush(meta_fp);

            snprintf(stream_name, 256, "/tmp/%ld_%s", global_syscall_cnt, ci->path);
            si->fp = fopen(stream_name, "w");
        } else if (si->domain == AF_INET) {
            char straddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ci->sin_addr, straddr, INET_ADDRSTRLEN);
            fprintf(meta_fp, "CONNECT %ld AF_INET addr: %s port %d\n", global_syscall_cnt, straddr, ci->port);
            fflush(meta_fp);

            snprintf(stream_name, 256, "/tmp/%ld_%s_%d", global_syscall_cnt, straddr, ci->port);
            si->fp = fopen(stream_name, "w");
        } else if (si->domain == AF_INET6) {
            char straddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ci->sin_addr6, straddr, INET6_ADDRSTRLEN);
            fprintf(meta_fp, "CONNECT %ld AF_INET6 addr: %s port %d\n", global_syscall_cnt, straddr, ci->port);
            fflush(meta_fp);

            snprintf(stream_name, 256, "/tmp/%ld_%s_%d", global_syscall_cnt, straddr, ci->port);
            si->fp = fopen(stream_name, "w");
        }
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
            open_stop((int) ret_value);
            break;
        case SYS_close:
            close_stop((int) ret_value);
            break;
        case SYS_readv:
            break;
        case SYS_writev:
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
                    write_stop((int) ret_value);
		    break;
                case SYS_SENDTO:
                    write_stop((int) ret_value);
                    break;
                case SYS_RECV:
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
void instrument_syscall(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2)
{   
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
	int sysnum = (int) syscall_num;
	
	fprintf (stderr, "%ld Pid %d, tid %d, (record pid %d), %d: syscall num is %d\n", global_syscall_cnt, PIN_GetPid(), PIN_GetTid(), tdata->record_pid, tdata->syscall_cnt, (int) syscall_num);

	if (sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	    check_clock_before_syscall (fd, (int) syscall_num);
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
        case SYS_open:
            open_start((char *)syscallarg0, (int)syscallarg1);
            break;
        case SYS_close:
            close_start((int)syscallarg0);
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
            if (check_clock_after_syscall (fd) == 0) {
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

    record_log_id = get_log_id (fd);
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
    ptdata->record_pid = get_record_pid();
    ptdata->syscall_cnt = 0;

    PIN_SetThreadData (tls_key, ptdata, threadid);

    set_pin_addr (fd, (u_long) ptdata);
}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* ptdata;
    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    fprintf(stderr, "Pid %d (recpid %d, tid %d) thread fini\n", PIN_GetPid(), ptdata->record_pid, PIN_GetTid());
}

VOID ImageLoad (IMG img, VOID *v)
{
	uint32_t id = IMG_Id (img);

	ADDRINT load_offset = IMG_LoadOffset(img);
	fprintf(stderr, "[IMG] Loading image id %d, name %s with load offset %#x\n",
			id, IMG_Name(img).c_str(), load_offset);
}

int main(int argc, char** argv) 
{    
    int rc;

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

    if (!open_fds) {
        struct open_info* oi;
        open_fds = new_xray_monitor(sizeof(struct open_info));
        
        // setup stdin/stdout/stderr fds
        oi = (struct open_info *) malloc(sizeof(struct open_info));
        strcpy(oi->filename, "stdin");
        oi->flags = 0;
        oi->fp = fopen("/tmp/stdin", "w");
        monitor_add_fd(open_fds, fileno(stdin), 0, oi);
        oi = (struct open_info *) malloc(sizeof(struct open_info));
        strcpy(oi->filename, "stdout");
        oi->flags = 0;
        oi->fp = fopen("/tmp/stdout", "w");
        monitor_add_fd(open_fds, fileno(stdout), 0, oi);
        oi = (struct open_info *) malloc(sizeof(struct open_info));
        strcpy(oi->filename, "stderr");
        oi->flags = 0;
        oi->fp = fopen("/tmp/stderr", "w");
        monitor_add_fd(open_fds, fileno(stderr), 0, oi);
    }

    if (!open_socks) {
        open_socks = new_xray_monitor(sizeof(struct socket_info));
    }

    // Intialize the replay device
    rc = devspec_init (&fd);
    if (rc < 0) return rc;

    meta_fp = fopen("/tmp/streams_info", "w");

    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);

    PIN_AddThreadStartFunction(thread_start, 0);
    PIN_AddThreadFiniFunction(thread_fini, 0);

    PIN_AddFollowChildProcessFunction(follow_child, argv);
    INS_AddInstrumentFunction(track_inst, 0);

    // Register a notification handler that is called when the application
    // forks a new process
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);

    IMG_AddInstrumentFunction (ImageLoad, 0);
    TRACE_AddInstrumentFunction (track_trace, 0);

    PIN_AddSyscallExitFunction(instrument_syscall_ret, 0);
    PIN_StartProgram();

    return 0;
}
