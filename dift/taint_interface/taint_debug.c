#include "taint_debug.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "taint_interface.h"

// not thread safe
static int write_exit = 0;

int is_dst_zero(void* ptdata, taint_op_t taint_op, u_long dst)
{
    if (is_dst_reg(taint_op)) {
        int i = 0;
        int size;
        taint_t* reg_taints;

        size = get_dst_size(taint_op);
        reg_taints = get_reg_taints(ptdata, (int) dst);
        for (i = 0; i < size; i++) {
            if (reg_taints[i]) {
                return 0;
            }
        }
        return 1;
    } else if (is_dst_mem(taint_op)) {
        int i;
        int size;
        taint_t* mem_taints;

        size = get_dst_size(taint_op);
        for (i = 0; i < size; i++) {
            mem_taints = get_mem_taints(dst + i, 1);
            if (mem_taints) {
                if (mem_taints[0]) {
                    return 0;
                }
            }
        }
        return 1;
    }
    return 1;
}

int is_src_zero(void* ptdata, taint_op_t taint_op, u_long src)
{
    if (is_src_reg(taint_op)) {
        int i = 0;
        int size;
        taint_t* reg_taints;

        size = get_src_size(taint_op);
        reg_taints = get_reg_taints(ptdata, (int) src);
        for (i = 0; i < size; i++) {
            if (reg_taints[i]) {
                return 0;
            }
        }
        return 1;
    } else if (is_src_mem(taint_op)) {
        int i;
        int size;
        taint_t* mem_taints;

        size = get_src_size(taint_op);
        for (i = 0; i < size; i++) {
            mem_taints = get_mem_taints(src + i, 1);
            if (mem_taints) {
                if (mem_taints[0]) {
                    return 0;
                }
            }
        }
        return 1;
    }
    return 1;
}

void trace_syscall_op(void* ptdata, int outfd, int threadid,
                        u_long ip, taint_op_t taint_op,
                        u_long syscall_num,
                        u_long syscall_cnt)
{
    int rc;
    struct taint_op op;
    op.ip = ip;
    op.threadid = threadid;
    op.taint_op = taint_op;
    op.dst = syscall_num; // stuff syscall num in here
    op.src = syscall_cnt; // put the global syscall cnt here

    rc = write(outfd, &op, sizeof(op));
    if (rc != sizeof(op)) {
        fprintf(stderr, "trace_taint_op: cannot write out taint op, got %d, expected %d, errno %d\n",
                rc, sizeof(op), errno);
    }
}

void trace_taint_op(void* ptdata, int outfd, int threadid,
                        u_long ip, taint_op_t taint_op,
                        u_long dst, u_long src)
{
    int rc;
    struct taint_op op;

    if (is_dst_zero(ptdata, taint_op, dst) && 
            is_src_zero(ptdata, taint_op, src)) {
        return;
    }

    op.ip = ip;
    op.threadid = threadid;
    op.taint_op = taint_op;
    op.dst = dst;
    op.src = src;

    rc = write(outfd, &op, sizeof(op));
    if (rc != sizeof(op)) {
        fprintf(stderr, "trace_taint_op: cannot write out taint op, got %d, expected %d, errno %d\n",
                rc, sizeof(op), errno);
    }

    if (taint_op == TAINT_REP_LBREG2MEM ||
            taint_op == TAINT_REP_UBREG2MEM ||
            taint_op == TAINT_REP_HWREG2MEM ||
            taint_op == TAINT_REP_WREG2MEM ||
            taint_op == TAINT_REP_DWREG2MEM ||
            taint_op == TAINT_REP_QWREG2MEM ||
            taint_op == TAINT_MEM2MEM)
    {
        return;
    }

    if (is_src_reg(taint_op)) {
        int size;
        taint_t* reg_taints;

        size = get_src_size(taint_op);
        reg_taints = get_reg_taints(ptdata, (int) src);

        rc = write(outfd, reg_taints, sizeof(taint_t) * size);
        if (rc != (sizeof(taint_t) * size)) {
            fprintf(stderr, "trace_taint_op: cannot write src reg taints, got %d, expected %d, errno %d\n",
                    rc, sizeof(taint_t) * size, errno);
        }
    } else if (is_src_mem(taint_op)) {
        int i;
        int size;
        taint_t* mem_taints;
        size = get_src_size(taint_op);

        for (i = 0; i < size; i++) {
            mem_taints = get_mem_taints(src + i, 1);
            if (mem_taints) {
                rc = write(outfd, mem_taints, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                            rc, sizeof(taint_t), errno);
                }
            } else {
                taint_t value = 0;
                rc = write(outfd, &value, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                            rc, sizeof(taint_t), errno);
                }
            }
        }
    }

    if (is_dst_reg(taint_op)) {
        int size;
        taint_t* reg_taints;

        size = get_dst_size(taint_op);
        reg_taints = get_reg_taints(ptdata, (int) dst);

        rc = write(outfd, reg_taints, sizeof(taint_t) * size);
        if (rc != (sizeof(taint_t) * size)) {
            fprintf(stderr, "trace_taint_op: cannot write dst reg taints, got %d, expacted %d, errno %d\n",
                    rc, sizeof(taint_t) * size, errno);
        }
    } else if (is_dst_mem(taint_op)) {
        int i;
        int size;
        taint_t* mem_taints;

        size = get_dst_size(taint_op);
        for (i = 0; i < size; i++) {
            mem_taints = get_mem_taints(src + i, 1);
            if (mem_taints) {
                rc = write(outfd, mem_taints, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                            rc, sizeof(taint_t), errno);
                }
            } else {
                taint_t value = 0;
                rc = write(outfd, &value, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                            rc, sizeof(taint_t), errno);
                }
            }
        }
    }
}

void trace_taint_op_enter(void* ptdata, int outfd, int threadid,
                        u_long ip, taint_op_t taint_op,
                        u_long dst, u_long src)
{
    int rc;
    struct taint_op op;
    int bytes_written = 0;

    if (is_dst_zero(ptdata, taint_op, dst) && 
            is_src_zero(ptdata, taint_op, src)) {
        return;
    }

    write_exit = 1;

    op.ip = ip;
    op.threadid = threadid;
    op.taint_op = taint_op;
    op.dst = dst;
    op.src = src;

    rc = write(outfd, &op, sizeof(op));
    if (rc != sizeof(op)) {
        fprintf(stderr, "trace_taint_op: cannot write out taint op, got %d, expected %d, errno %d\n",
                rc, sizeof(op), errno);
    }
    bytes_written += rc;

    if (is_src_reg(taint_op)) {
        int size;
        taint_t* reg_taints;

        size = get_src_size(taint_op);
        reg_taints = get_reg_taints(ptdata, (int) src);

        rc = write(outfd, reg_taints, sizeof(taint_t) * size);
        if (rc != (sizeof(taint_t) * size)) {
            fprintf(stderr, "trace_taint_op: cannot write src reg taints, got %d, expected %d, errno %d\n",
                    rc, sizeof(taint_t) * size, errno);
        }
        bytes_written += rc;
    } else if (is_src_mem(taint_op)) {
        int i;
        int size;
        taint_t* mem_taints;
        size = get_src_size(taint_op);

        for (i = 0; i < size; i++) {
            mem_taints = get_mem_taints(src + i, 1);
            if (mem_taints) {
                rc = write(outfd, mem_taints, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                            rc, sizeof(taint_t), errno);
                }
                bytes_written += rc;
            } else {
                taint_t value = 0;
                rc = write(outfd, &value, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                            rc, sizeof(taint_t), errno);
                }
                bytes_written += rc;
            }
        }
    }
}

void trace_taint_op_exit(void* ptdata, int outfd, int threadid,
                        u_long ip, taint_op_t taint_op,
                        u_long dst, u_long src)
{
    int rc;
    int bytes_written = 0;

    // same condition needs to hold for enter and exit to hold
    if (!write_exit) {
        return;
    }
    assert(write_exit);
    write_exit = 0;

    // only write out dst taints, the header and src taints are written out
    //  in the enter function
    if (is_dst_reg(taint_op)) {
        int size;
        taint_t* reg_taints;

        size = get_dst_size(taint_op);
        reg_taints = get_reg_taints(ptdata, (int) dst);

        rc = write(outfd, reg_taints, sizeof(taint_t) * size);
        if (rc != (sizeof(taint_t) * size)) {
            fprintf(stderr, "trace_taint_op: cannot write dst reg taints, got %d, expacted %d, errno %d\n",
                    rc, sizeof(taint_t) * size, errno);
        }
        bytes_written += rc;
    } else if (is_dst_mem(taint_op)) {
        int i;
        int size;
        taint_t* mem_taints;

        size = get_dst_size(taint_op);
        for (i = 0; i < size; i++) {
            mem_taints = get_mem_taints(dst + i, 1);
            if (mem_taints) {
                rc = write(outfd, mem_taints, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                            rc, sizeof(taint_t), errno);
                }
                bytes_written += rc;
            } else {
                taint_t value = 0;
                rc = write(outfd, &value, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                            rc, sizeof(taint_t), errno);
                }
                bytes_written += rc;
            }
        }
    } else {
        assert(0);
    }

    if (taint_op == TAINT_LBREG2MEM) {
        fprintf(stderr, "taint_lbreg2mem wrote %d\n", bytes_written);
    }
}



/*
 * Read one taint op from infd
 * Returns the number of bytes read
 */
int read_taint_op(int infd, struct taint_op* op)
{
    int rc;
    taint_op_t taint_op;
    int bytes_read = 0;

    assert(op);
    rc = read(infd, op, sizeof(struct taint_op));
    if (rc != sizeof(struct taint_op)) {
        fprintf(stderr, "read_taint_op: cannot read taint op, got %d, expected %d, errno %d\n",
                rc, sizeof(struct taint_op), errno);
        exit(-1);
    }
    bytes_read += rc;
    taint_op = op->taint_op;
    fprintf(stderr, "read taint op: %d\n", taint_op);

    if (is_src_reg(taint_op)) {
        int i = 0;
        int size;
        taint_t t;

        size = get_src_size(taint_op);
        // read size number of taints
        for (i = 0; i < size; i++) {
            rc = read(infd, &t, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "read_taint_op: cannot read src reg taint\n");
                assert(0);
            }
            bytes_read += rc;
        }
    } else if (is_src_mem(taint_op)) {
        int i;
        int size;
        taint_t t;
        size = get_src_size(taint_op);

        for (i = 0; i < size; i++) {
            rc = read(infd, &t, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "read_taint_op: cannot read src mem taint\n");
            }
            bytes_read += rc;
        }
    }

    if (is_dst_reg(taint_op)) {
        int i = 0;
        int size;
        taint_t t;

        size = get_dst_size(taint_op);
        // read size number of taints
        for (i = 0; i < size; i++) {
            rc = read(infd, &t, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "read_taint_op: cannot read dst reg taint\n");
                assert(0);
            }
            bytes_read += rc;
        }
    } else if (is_dst_mem(taint_op)) {
        int i;
        int size;
        taint_t t;

        size = get_dst_size(taint_op);
        for (i = 0; i < size; i++) {
            rc = read(infd, &t, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "read_taint_op: cannot read dst mem taint\n");
            }
            bytes_read += rc;
        }
    }

    return bytes_read;
}
