#include "taint_debug.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "taint_interface.h"

// not thread safe
static int write_exit = 0;
static uint16_t g_dst_taint = 0;
static uint16_t g_src_taint = 0;

static inline uint16_t get_mem_taint(u_long mem_loc)
{
    uint32_t* qw_mem;
    int offset = (mem_loc % 8);
    qw_mem = (uint32_t *) get_mem_taints(mem_loc, 4);
    return (*qw_mem) >> offset;
}

static uint16_t get_t_mask(uint16_t t, int size)
{
    uint16_t t_mask;
    if (size == 1) {
        t_mask = t & 0x1;
    } else if (size == 2) {
        t_mask = t & 0x3;
    } else if (size == 4) {
        t_mask = t & 0xf;
    } else if (size == 8) {
        t_mask = t & 0xff;
    } else if (size == 16) {
        t_mask = t & 0xffff;
    } else {
        t_mask = t;
    }
    return t_mask;
}

int is_dst_zero(void* ptdata, taint_op_t taint_op, u_long dst)
{
    if (is_dst_reg(taint_op)) {
        int size;
        uint16_t reg_taints;
        reg_taints = * (uint16_t *) get_reg_taints(ptdata, (int) dst);
        size = get_dst_size(taint_op);
        reg_taints = get_t_mask(reg_taints, size);
        if (reg_taints) {
            return 0;
        }
        return 1;
    } else if (is_dst_mem(taint_op)) {
        int size;
        uint16_t mem_taints;
        mem_taints = get_mem_taint(dst);
        size = get_dst_size(taint_op);
        mem_taints = get_t_mask(mem_taints, size);
        if (mem_taints) {
            return 0;
        }
        return 1;
    }
    return 1;
}

int is_src_zero(void* ptdata, taint_op_t taint_op, u_long src)
{
    if (is_src_reg(taint_op)) {
        int size;
        uint16_t reg_taints;
        reg_taints = * (uint16_t *) get_reg_taints(ptdata, (int) src);
        size = get_src_size(taint_op);
        reg_taints = get_t_mask(reg_taints, size);
        if (reg_taints) {
            return 0;
        }
        return 1;
    } else if (is_src_mem(taint_op)) {
        int size;
        uint16_t mem_taints;
        mem_taints = get_mem_taint(src);
        size = get_src_size(taint_op);
        mem_taints = get_t_mask(mem_taints, size);
        if (mem_taints) {
            return 0;
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
    uint16_t dst_taint = 0;
    uint16_t src_taint = 0;

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
        uint16_t reg_taints;
        reg_taints = * (uint16_t *) get_reg_taints(ptdata, (int) src);
        reg_taints = get_t_mask(reg_taints, get_src_size(taint_op));
        rc = write(outfd, &reg_taints, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "trace_taint_op: cannot write src reg taints, got %d, expected %d, errno %d\n",
                    rc, sizeof(uint16_t), errno);
        }
        src_taint = reg_taints;
    } else if (is_src_mem(taint_op)) {
        uint16_t mem_taints;
        mem_taints = get_mem_taint(src);
        mem_taints = get_t_mask(mem_taints, get_src_size(taint_op));
        rc = write(outfd, &mem_taints, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                    rc, sizeof(uint16_t), errno);
        }
        src_taint = mem_taints;
        // TODO if size > 16
        // size = get_src_size(taint_op);
    }

    if (is_dst_reg(taint_op)) {
        uint16_t reg_taints;
        reg_taints = * (uint16_t *) get_reg_taints(ptdata, (int) dst);
        reg_taints = get_t_mask(reg_taints, get_dst_size(taint_op));
        rc = write(outfd, &reg_taints, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "trace_taint_op: cannot write dst reg taints, got %d, expacted %d, errno %d\n",
                    rc, sizeof(uint16_t), errno);
        }
        dst_taint = reg_taints;
    } else if (is_dst_mem(taint_op)) {
        uint16_t mem_taints;
        mem_taints = get_mem_taint(dst);
        mem_taints = get_t_mask(mem_taints, get_dst_size(taint_op));
        rc = write(outfd, &mem_taints, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                    rc, sizeof(uint16_t), errno);
        }
        dst_taint = mem_taints;
        // TODO if size > 16
        // size = get_dst_size(taint_op);
    }
    assert(dst_taint || src_taint);
}

void trace_taint_op_enter(void* ptdata, int outfd, int threadid,
                        u_long ip, taint_op_t taint_op,
                        u_long dst, u_long src)
{
    int rc;
    struct taint_op op;

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

    if (is_src_reg(taint_op)) {
        uint16_t reg_taints;
        reg_taints = * (uint16_t *) get_reg_taints(ptdata, (int) src);
        reg_taints = get_t_mask(reg_taints, get_src_size(taint_op));
        rc = write(outfd, &reg_taints, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "trace_taint_op: cannot write src reg taints, got %d, expected %d, errno %d\n",
                    rc, sizeof(uint16_t), errno);
        }
        g_src_taint = reg_taints;
    } else if (is_src_mem(taint_op)) {
        uint16_t mem_taints;
        mem_taints = get_mem_taint(src);
        mem_taints = get_t_mask(mem_taints, get_src_size(taint_op));
        rc = write(outfd, &mem_taints, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                    rc, sizeof(uint16_t), errno);
        }
        g_src_taint = mem_taints;
        // TODO if size > 16
        // size = get_src_size(taint_op);
    }

    if (is_dst_reg(taint_op)) {
        uint16_t reg_taints;
        reg_taints = * (uint16_t *) get_reg_taints(ptdata, (int) dst);
        reg_taints = get_t_mask(reg_taints, get_dst_size(taint_op));
        g_dst_taint = reg_taints;
    } else if (is_dst_mem(taint_op)) {
        uint16_t mem_taints;
        mem_taints = get_mem_taint(dst);
        mem_taints = get_t_mask(mem_taints, get_dst_size(taint_op));
        g_dst_taint = mem_taints;
    }

    if (!(g_dst_taint || g_src_taint)) {
        fprintf(stderr, "taint op %s zero fail\n", taint_op_str(taint_op));
        fprintf(stderr, "is_dst_zero %d, g_dst_taint %d\n", is_dst_zero(ptdata, taint_op, dst), g_dst_taint);
        fprintf(stderr, "is_src_zero %d, g_src_taint %d\n", is_src_zero(ptdata, taint_op, src), g_src_taint);
    }
    assert(g_dst_taint || g_src_taint);
}

void trace_taint_op_exit(void* ptdata, int outfd, int threadid,
                        u_long ip, taint_op_t taint_op,
                        u_long dst, u_long src)
{
    int rc;

    // same condition needs to hold for enter and exit to hold
    if (!write_exit) {
        return;
    }
    assert(write_exit);
    write_exit = 0;

    uint16_t old_taint = g_dst_taint;
    //
    // only write out dst taints, the header and src taints are written out
    //  in the enter function
    if (is_dst_reg(taint_op)) {
        uint16_t reg_taints;
        reg_taints = * (uint16_t *) get_reg_taints(ptdata, (int) dst);
        reg_taints = get_t_mask(reg_taints, get_dst_size(taint_op));
        rc = write(outfd, &reg_taints, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "trace_taint_op: cannot write dst reg taints, got %d, expacted %d, errno %d\n",
                    rc, sizeof(uint16_t), errno);
        }
        g_dst_taint = reg_taints;
    } else if (is_dst_mem(taint_op)) {
        uint16_t mem_taints;
        mem_taints = get_mem_taint(dst);
        mem_taints = get_t_mask(mem_taints, get_dst_size(taint_op));
        rc = write(outfd, &mem_taints, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "trace_taint_op: cannot write mem taint, got %d, expected %d, errno %d\n",
                    rc, sizeof(uint16_t), errno);
        }
        // TODO if size > 16
        // size = get_dst_size(taint_op);
        g_dst_taint = mem_taints;
    } else {
        assert(0);
    }

    if (!(g_dst_taint || g_src_taint)) {
        fprintf(stderr, "taint op %s zero fail\n", taint_op_str(taint_op));
        fprintf(stderr, "dst %lx, src %lx\n", dst, src);
        fprintf(stderr, "old taint %x\n", old_taint);
        fprintf(stderr, "is_dst_zero %d, g_dst_taint %d\n", is_dst_zero(ptdata, taint_op, dst), g_dst_taint);
        fprintf(stderr, "is_src_zero %d, g_src_taint %d\n", is_src_zero(ptdata, taint_op, src), g_src_taint);
    }
    // assert(g_dst_taint || g_src_taint);

    g_dst_taint = 0;
    g_src_taint = 0;
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

