#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib-2.0/glib.h>
#include "taint_debug.h"
#include "taint_interface.h"

#include "../xray_slab_alloc.h"
#include "taint_creation.h"
#include "../xray_token.h"

int start = 1;

GHashTable* taint_operations_table = NULL;

unsigned long taint_op_count = 0;

/*
 * Read one taint op from infd
 * Returns the number of bytes read
 */
int read_taint_op_extended(int infd, struct taint_op* op, int mergenumbers)
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

    if (taint_op == TAINTOP_SYSCALL) {
        fprintf(stdout, "SYSCALL %lu, num %lu\n",
                                    op->src, op->dst);
        taint_op_count++;
        return bytes_read;
    }

    if (start) {
        fprintf(stdout, "%lu taint op: %lx %d %d %s\n", taint_op_count, op->ip,
                op->threadid, op->taint_op, taint_op_str(op->taint_op));
        fflush(stdout);
    }

    if (taint_op == TAINT_REP_LBREG2MEM ||
            taint_op == TAINT_REP_UBREG2MEM ||
            taint_op == TAINT_REP_HWREG2MEM ||
            taint_op == TAINT_REP_WREG2MEM ||
            taint_op == TAINT_REP_DWREG2MEM ||
            taint_op == TAINT_REP_QWREG2MEM ||
            taint_op == TAINT_MEM2MEM)
    {
        taint_op_count++;
        return bytes_read;
    }

    if (is_src_reg(taint_op)) {
        uint16_t t;
        rc = read(infd, &t, sizeof(uint16_t));
        if (t && !start) {
            start = 1;
            fprintf(stdout, "%lu taint op: %lx %d %d %s\n", taint_op_count, op->ip,
                    op->threadid, op->taint_op, taint_op_str(op->taint_op));
        }
        if (start) {
            if (t) {
                fprintf(stdout, " src(%lu): %x\n", op->src, t);
            }
            fprintf(stdout, "source(%lu) t is %x\n", op->src, t);
        }
        bytes_read += rc;
    } else if (is_src_mem(taint_op)) {
        int i;
        int size;
        uint16_t t;
        size = get_src_size(taint_op);
        assert(size != 0);

        rc = read(infd, &t, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "read_taint_op: cannot read src mem taint\n");
        }
        if (t && !start) {
            start = 1;
            fprintf(stdout, "%lu taint op: %lx %d %d %s\n", taint_op_count, op->ip,
                    op->threadid, op->taint_op, taint_op_str(op->taint_op));
        }
        if (start) {
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
            if (t_mask) {
                fprintf(stdout, " src(%#lx) %x\n", op->src, t_mask);
                for (i = 0; i < size; i++) {
                    fprintf(stdout, " src(%#lx) %d\n", op->src + i, 1);
                }
            }
        }
        bytes_read += rc;
    } else {
        assert(0);
    }

    if (is_dst_reg(taint_op)) {
        uint16_t t;
        rc = read(infd, &t, sizeof(uint16_t));
        if (t && !start) {
            start = 1;
            fprintf(stdout, "%lu taint op: %lx %d %d %s\n", taint_op_count, op->ip,
                    op->threadid, op->taint_op, taint_op_str(op->taint_op));
        }
        if (start) {
            if (t) {
                fprintf(stdout, " dst(%lu) %x\n", op->dst, t);
            }
        }
        bytes_read += rc;
    } else if (is_dst_mem(taint_op)) {
        int i;
        int size;
        uint16_t t;
        size = get_dst_size(taint_op);
        rc = read(infd, &t, sizeof(uint16_t));
        if (rc != sizeof(uint16_t)) {
            fprintf(stderr, "read_taint_op: cannot read dst mem taint\n");
        }
        if (start) {
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
            //fprintf(stdout, " dst(%#lx) %x\n", op->dst, t_mask);
            // fprintf(stdout, " t is %x, size is %d\n", t, size);
            if (t_mask) {
                fprintf(stdout, " dst(%#lx) %x\n", op->dst, t_mask);
                fprintf(stdout, " t is %x, size is %d\n", t, size);
                for (i = 0; i < size; i++) {
                    fprintf(stdout, " dst(%#lx) %d\n", op->dst + i, 1);
                }
            } else {
                fprintf(stdout, " dst(%#lx) cleared\n", op->dst);
            }
        }
        bytes_read += rc;
    } else {
        assert(0);
    }

    taint_op_count++;
    return bytes_read;
}


void print_taint_kv(gpointer key, gpointer value, gpointer user_data)
{
    fprintf(stdout, "%d(%s), %d\n",
            GPOINTER_TO_INT(key),
            taint_op_str((taint_op_t)GPOINTER_TO_INT(key)),
            GPOINTER_TO_INT(value));
}

/* Prints all of the taint ops used */
void print_unique_taint_ops(GHashTable* taint_operations_table)
{
    assert(taint_operations_table);

    g_hash_table_foreach(taint_operations_table, print_taint_kv, NULL);
}

void usage()
{
    printf("Usage: ./taint_debugger <directory>\n");
}

int taint_debug(int argc, char** argv)
{
    int infd = 0;
    struct taint_op top;
    long taint_ops = 0;
    struct stat buf;
    int rc;
    loff_t bytes_read = 0;

    char* group_dir;
    char debug_filename[256];

    if (argc < 2) {
        usage();
    }

    group_dir = argv[1];
    snprintf(debug_filename, 256, "%s/trace_taint_ops", group_dir);

    taint_operations_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    infd = open(debug_filename, O_RDONLY | O_LARGEFILE);
    if (infd < 0) {
        fprintf(stderr, "could not open %s, rc %d, errno %d\n", debug_filename, infd, errno);
        exit(-1);
    }
    rc = fstat(infd, &buf);
    if (rc == -1) {
        fprintf(stderr, "could not stat debug file: %s, errno %d\n", debug_filename, errno);
        exit(-1);
    }

    while(bytes_read < buf.st_size) {
        bytes_read += read_taint_op_extended(infd, &top, 1);

        g_hash_table_insert(taint_operations_table,
                                GINT_TO_POINTER(top.taint_op),
                                GINT_TO_POINTER(1));

        taint_ops++;
        if (taint_ops % 1000000 == 0) {
            fprintf(stdout, "num taint ops %ld\n", taint_ops);
        }
    }
    fprintf(stdout, "debug done\n");

    print_unique_taint_ops(taint_operations_table);   

    return 0;
}

int main(int argc, char** argv)
{
    return taint_debug(argc, argv);
}

