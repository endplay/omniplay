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

GHashTable* leaf_node_table = NULL;
GHashTable* merge_node_table = NULL;
GHashTable* merge_index_table = NULL;

GHashTable* filename_table = NULL;
GHashTable* option_info_table = NULL;

GHashTable* taint_operations_table = NULL;

unsigned long taint_op_count = 0;

// redefine here
struct taint_node {
    struct taint_node* parent1;
    struct taint_node* parent2;
};
struct taint_leafnode {
    struct taint_node node;
    u_long option;
};

// redefine here.
struct taint_number {
    u_long n;
    u_long p1;
    u_long p2;
};

void parse_taint_structures(char* taint_structures_filename,
                            GHashTable* leaf_node_table,
                            GHashTable* merge_node_table,
                            GHashTable* merge_index_table)
{
    int i = 0;
    int fd;
    int rc;
    // int num_merge_indices = 0;
    struct slab_alloc leaf_alloc;
    struct slab_alloc node_alloc;
    struct stat buf;
    off_t offset;
    int merge_index_size = sizeof(uint64_t) + sizeof(u_long);
    unsigned long leaf_num_slices = 0;
    unsigned long node_num_slices = 0;
    //int node_num_slices = 0;
    unsigned long leaf_slices_per_slab = 0;
    unsigned long node_slices_per_slab = 0;
    int j;

    int num_leaves = 0;
    int num_nodes = 0;

    assert (leaf_node_table);
    assert (merge_node_table);
    assert (merge_index_table);

    fd = open(taint_structures_filename, O_RDONLY);

    rc = fstat(fd, &buf);
    if (rc == -1) {
        fprintf(stderr, "Could not state taint_structures file, errno %d\n",
                errno);
    }

    rc = read(fd, &leaf_alloc, sizeof(struct slab_alloc));
    if (rc != sizeof(struct slab_alloc)) {
    }

    leaf_num_slices = leaf_alloc.num_slices;
    leaf_slices_per_slab = leaf_alloc.slab_size / leaf_alloc.slice_size;
    for (i = 0; i < leaf_alloc.num_slabs; i++) {
        struct slab s;
        void* slab;
        int num_slices = 0;
        slab = malloc(leaf_alloc.slab_size);

        assert (leaf_num_slices > 0);

        if (leaf_num_slices > leaf_slices_per_slab) {
            num_slices = leaf_slices_per_slab;
            leaf_num_slices -= num_slices;
        } else {
            num_slices = leaf_num_slices;
            leaf_num_slices = 0;
        }

        rc = read(fd, &s, sizeof(struct slab));
        if (rc != sizeof(struct slab)) {
            fprintf(stderr, "could not read slab header\n");
            assert(0);
        }

        // read each of the slices
        rc = read(fd, slab, leaf_alloc.slab_size);
        if (rc != leaf_alloc.slab_size) {
            fprintf(stderr, "could not fully read slab, expected %d, got %d, errno %d\n", leaf_alloc.slab_size, rc, errno);
            assert(0);
        }
        for (j = 0; j < num_slices; j++) {
            u_long new_addr;
            u_long orig_addr;
            // struct taint_leafnode* tln;

            new_addr = ((u_long) slab) + j * (leaf_alloc.slice_size);
            orig_addr = ((u_long) s.start) + j * (leaf_alloc.slice_size);
            // fprintf(stderr, "leaf orig addr: %lu, new addr: %lu\n", orig_addr, new_addr);

            // Original -> new
            g_hash_table_insert(leaf_node_table, (gpointer) orig_addr, (gpointer) new_addr);
            num_leaves++;
        }
    }

    rc = read(fd, &node_alloc, sizeof(struct slab_alloc));
    if (rc != sizeof(struct slab_alloc)) {
        fprintf(stderr, "could not read node slab alloc\n");
        assert(0);
    }

    node_num_slices = node_alloc.num_slices;
    node_slices_per_slab = node_alloc.slab_size / node_alloc.slice_size;
    for (i = 0; i < node_alloc.num_slabs; i++) {
        struct slab s;
        void* slab;
        int num_slices = 0;
        slab = malloc(node_alloc.slab_size);

        assert (node_num_slices >= 0);
        if (node_num_slices > node_slices_per_slab) {
            num_slices = node_slices_per_slab;
            node_num_slices -= num_slices;
        } else {
            num_slices = node_num_slices;
            node_num_slices = 0;
        }

        rc = read(fd, &s, sizeof(struct slab));
        if (rc != sizeof(struct slab)) {
            fprintf(stderr, "could not read slab header\n");
            assert(0);
        }

        rc = read(fd, slab, node_alloc.slab_size);
        if (rc != node_alloc.slab_size) {
            fprintf(stderr, "could not fully read slab, expected %d, got %d, errno %d\n", node_alloc.slab_size, rc, errno);
            assert(0);
        }
        for (j = 0; j < num_slices; j++) {
            u_long new_addr;
            u_long orig_addr;

            new_addr = ((u_long) slab) + j * (node_alloc.slice_size);
            orig_addr = ((u_long) s.start) + j * (node_alloc.slice_size);
            // fprintf(stderr, "node orig addr: %lu, new addr: %lu\n", orig_addr, new_addr);
            // fprintf(stderr, " p1 orig addr: %lu\n", (u_long) ((struct taint_node *) new_addr)->parent1);
            // fprintf(stderr, " p2 orig addr: %lu\n", (u_long) ((struct taint_node *) new_addr)->parent2);

            // Original -> new
            g_hash_table_insert(merge_node_table, (gpointer) orig_addr, (gpointer) new_addr);
            num_nodes++;
        }
    }

    // node read the merge indices
    // calculate how many are left using the offset of the file
    offset = lseek(fd, 0, SEEK_CUR);
    assert((buf.st_size - offset) % merge_index_size == 0);
    // num_merge_indices = (buf.st_size - offset) / merge_index_size;
    /*

    for (i = 0; i < num_merge_indices; i++) {
        uint64_t* phash;
        u_long node;
        phash = (uint64_t *) malloc(sizeof(uint64_t));


        rc = read(fd, phash, sizeof(uint64_t));
        if (rc != sizeof(uint64_t)) {
            fprintf(stderr, "cannot read size of hash?\n");
            assert(0);
        }

        rc = read(fd, &node, sizeof(u_long));
        if (rc != sizeof(u_long)) {
            fprintf(stderr, "cannot read size of node ptr?\n");
            assert(0);
        }

        g_hash_table_insert (merge_index_table, phash, GUINT_TO_POINTER(node));
        fprintf(stderr, "%llu %lu\n", *phash, node);
    }
    */

    close(fd);
}


void print_leaf_options(struct taint_creation_info* tci,
                            u_long taint,
                            int output_byte_offset,
                            GHashTable* leaf_node_table,
                            GHashTable* merge_node_table,
                            GHashTable* option_info_table,
                            GHashTable* filename_table)
{
    u_long new_addr;
    GHashTable* seen_indices;
    GQueue* queue;

    seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    queue = g_queue_new();

    assert(taint);
    assert(tci);

    if (g_hash_table_contains(leaf_node_table, (gpointer) taint)) {
        new_addr = (u_long) g_hash_table_lookup(leaf_node_table, (gpointer) taint);
    } else {
        new_addr = (u_long) g_hash_table_lookup(merge_node_table, (gpointer) taint);
    }
    if (!new_addr) {
        fprintf(stderr, "Could not find taint: %lu\n", (u_long) taint);
        return;
    }
    assert(new_addr);

    // Invariant: the addresses on the queue should always be the new addresses of the nodes
    g_queue_push_tail(queue, (gpointer) new_addr);
    while(!g_queue_is_empty(queue)) {
        struct taint_node* n;
        new_addr = (u_long) g_queue_pop_head(queue);
        assert(new_addr);

        if (g_hash_table_lookup(seen_indices, (gpointer) new_addr)) {
            continue;
        }
        g_hash_table_insert(seen_indices, (gpointer) new_addr, GINT_TO_POINTER(1));
        n = (struct taint_node *) new_addr;

        if (!n->parent1 && !n->parent2) { // leaf node
            char* filename = (char *) "--";
            struct token* tok;
            struct taint_leafnode* ln = (struct taint_leafnode *) n;
            
            // lookup option number to metadata describing that option
            tok = (struct token *) g_hash_table_lookup(option_info_table, GINT_TO_POINTER(ln->option));
            assert(tok);

            // resolve filenames
            if (g_hash_table_contains(filename_table, GINT_TO_POINTER(tok->fileno))) {
                filename = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(tok->fileno));
            }

            fprintf(stdout, "%llu %d %d %d %s",
                                tok->rg_id,
                                tok->record_pid,
                                tok->syscall_cnt,
                                tok->byte_offset,
                                filename);
            fprintf(stdout, "\n");
        } else {
            if (!g_hash_table_lookup(seen_indices, (gpointer) n->parent1)) {
                struct taint_node* p1;
                // lookup the address of the parent
                if (g_hash_table_contains(leaf_node_table, (gpointer) n->parent1)) {
                    p1 = (struct taint_node *) g_hash_table_lookup(leaf_node_table, (gpointer) n->parent1);
                } else {
                    p1 = (struct taint_node *) g_hash_table_lookup(merge_node_table, (gpointer) n->parent1);
                }
                assert(p1);
                // push the new address onto the queue
                g_queue_push_tail(queue, p1);
            }
            if (!g_hash_table_lookup(seen_indices, n->parent2)) {
                struct taint_node* p2;
                // lookup the address of the parent
                if (g_hash_table_contains(leaf_node_table, (gpointer) n->parent2)) {
                    p2 = (struct taint_node *) g_hash_table_lookup(leaf_node_table, (gpointer) n->parent2);
                } else {
                    p2 = (struct taint_node *) g_hash_table_lookup(merge_node_table, (gpointer) n->parent2);
                }
                assert(p2);
                // push the new address onto the queue
                g_queue_push_tail(queue, p2);
            }
        }
    }
    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
}

void print_merge_numbers(taint_t taint_number,
                            GHashTable* merge_node_table,
                            GHashTable* option_info_table, 
                            GHashTable* filename_table)
{
    GHashTable* seen_indices;
    GQueue* queue;

    seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    queue = g_queue_new();

    assert(taint_number);

    g_queue_push_tail(queue, GUINT_TO_POINTER(taint_number));
    while(!g_queue_is_empty(queue)) {
        struct taint_number* tn;
        u_long n = GPOINTER_TO_UINT(g_queue_pop_head(queue));
        assert(n);
        tn = (struct taint_number *) g_hash_table_lookup(merge_node_table, GUINT_TO_POINTER(n));
        assert(tn);

        if (g_hash_table_lookup(seen_indices, GUINT_TO_POINTER(n))) {
            continue;
        }
        g_hash_table_insert(seen_indices, GUINT_TO_POINTER(n), 
                                            GINT_TO_POINTER(1));
        if (!tn->p1 && !tn->p2) { // leaf node
            char* filename = (char *) "--";
            struct token* tok;
            // lookup option number to metadata describing that option
            tok = (struct token *) g_hash_table_lookup(option_info_table, GINT_TO_POINTER(n));
            assert(tok);
            // resolve filenames
            if (g_hash_table_contains(filename_table, GINT_TO_POINTER(tok->fileno))) {
                filename = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(tok->fileno));
            }

            fprintf(stdout, "%llu %d %d %d %s",
                                tok->rg_id,
                                tok->record_pid,
                                tok->syscall_cnt,
                                tok->byte_offset,
                                filename);
            fprintf(stdout, "\n");
        } else {
            if (!g_hash_table_lookup(seen_indices, GUINT_TO_POINTER(tn->p1))) {
                assert(tn->p1);
                g_queue_push_tail(queue, GUINT_TO_POINTER(tn->p1));
            }
            if (!g_hash_table_lookup(seen_indices, GUINT_TO_POINTER(tn->p2))) {
                assert(tn->p2);
                g_queue_push_tail(queue, GUINT_TO_POINTER(tn->p2));
            }
        }
    }
    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
}

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
        int i = 0;
        int size;
        taint_t t;

        size = get_src_size(taint_op);
        assert(size != 0);
        // read size number of taints
        for (i = 0; i < size; i++) {
            rc = read(infd, &t, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "read_taint_op: cannot read src reg taint\n");
                assert(0);
            }
            if (t != 0 && !start) {
                start = 1;
                fprintf(stdout, "%lu taint op: %lx %d %d %s\n", taint_op_count, op->ip,
                        op->threadid, op->taint_op, taint_op_str(op->taint_op));
            }
            if (start) {
                if (t) {
                    struct taint_creation_info tci;
                    fprintf(stdout, " src(%lu) %d: ", op->src, i);
                    if (!mergenumbers) {
                        print_leaf_options(&tci, t, 0,
                                        leaf_node_table,
                                        merge_node_table,
                                        option_info_table,
                                        filename_table);
                    } else {
                        print_merge_numbers(t, merge_node_table,
                                            option_info_table,
                                            filename_table);
                    }
                }
            }
            bytes_read += rc;
        }
    } else if (is_src_mem(taint_op)) {
        int i;
        int size;
        taint_t t;
        size = get_src_size(taint_op);
        assert(size != 0);

        for (i = 0; i < size; i++) {
            rc = read(infd, &t, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "read_taint_op: cannot read src mem taint\n");
            }
            if (t != 0 && !start) {
                start = 1;
                fprintf(stdout, "%lu taint op: %lx %d %d %s\n", taint_op_count, op->ip,
                        op->threadid, op->taint_op, taint_op_str(op->taint_op));
            }
            if (start) {
                if (t) {
                    struct taint_creation_info tci;
                    fprintf(stdout, " src(%#lx) %d: ", op->src + i, i);
                    if (!mergenumbers) {
                        print_leaf_options(&tci, t, 0,
                                        leaf_node_table,
                                        merge_node_table,
                                        option_info_table,
                                        filename_table);
                    } else {
                        print_merge_numbers(t, merge_node_table,
                                            option_info_table,
                                            filename_table);
                    }
                }
            }
            bytes_read += rc;
        }
    } else {
        fprintf(stderr, "what is it %d %s\n", taint_op, taint_op_str(taint_op));
        assert(0);
    }

    if (is_dst_reg(taint_op)) {
        int i = 0;
        int size;
        taint_t t;

        size = get_dst_size(taint_op);
        if (size == 0) {
            fprintf(stderr, "taint_op size is 0?! %d %s\n",
                    taint_op, taint_op_str(taint_op));
        }
        assert(size != 0);
        // read size number of taints
        for (i = 0; i < size; i++) {
            rc = read(infd, &t, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "read_taint_op: cannot read dst reg taint\n");
                assert(0);
            }
            if (start) {
                if (t) {
                    struct taint_creation_info tci;
                    fprintf(stdout, " dst(%lu) %d: ", op->dst, i);
                    if (!mergenumbers) {
                        print_leaf_options(&tci, t, 0,
                                        leaf_node_table,
                                        merge_node_table,
                                        option_info_table,
                                        filename_table);
                    } else {
                        print_merge_numbers(t, merge_node_table,
                                            option_info_table,
                                            filename_table);
                    }
                }
            }

            bytes_read += rc;
        }
    } else if (is_dst_mem(taint_op)) {
        int i;
        int size;
        taint_t t;

        size = get_dst_size(taint_op);
        if (size == 0) {
            fprintf(stderr, "taint_op %d %s\n", taint_op, taint_op_str(taint_op));
            if (taint_op == TAINT_ADD_HWREG2MEM) goto done;
        }
        assert(size != 0);
        for (i = 0; i < size; i++) {
            rc = read(infd, &t, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "read_taint_op: cannot read dst mem taint\n");
            }
            if (start) {
                if (t || taint_op == TAINT_QWREG2MEM) {
                    struct taint_creation_info tci;
                    fprintf(stdout, " dst(%#lx) %d: ", op->dst + i, i);
                    if (!t) fprintf(stdout, "0\n");
                    else {
                        if (!mergenumbers) {
                            print_leaf_options(&tci, t, 0,
                                        leaf_node_table,
                                        merge_node_table,
                                        option_info_table,
                                        filename_table);
                        } else {
                            print_merge_numbers(t, merge_node_table,
                                                option_info_table,
                                                filename_table);
                        }
                    }
                } else {
                    fprintf(stdout, " dst(%#lx) cleared\n", op->dst + i);
                }
            }

            bytes_read += rc;
        }
    } else {
        assert(0);
    }

done:
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

int read_merge_numbers(char* taint_numbers_filename,
                        GHashTable* merge_node_table)
{
    struct stat buf;
    int fd;
    int rc;
    long bytes_read = 0;

    fd = open(taint_numbers_filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "problem reading %s, errno %d\n",
                        taint_numbers_filename, errno);
        return errno;
    }

    rc = fstat(fd, &buf);
    if (rc == -1) {
        fprintf(stderr, "problem statting %s, errno %d\n",
                        taint_numbers_filename, errno);
        return errno;
    }

    assert(buf.st_size % sizeof(struct taint_number) == 0);
    while(bytes_read < buf.st_size) {
        struct taint_number *tn;
        tn = (struct taint_number *) malloc(sizeof(struct taint_number));
        rc = read(fd, tn, sizeof(struct taint_number));
        if (rc != sizeof(struct taint_number)) {
            fprintf(stderr, "problem reading in a taint number, errno %d\n",
                                errno);
            rc = errno;
            goto exit;
        }
        // insert into hashtable
        g_hash_table_insert(merge_node_table, GINT_TO_POINTER(tn->n), tn);
        bytes_read += rc;
    }
    rc = 0;
exit:
    close(fd);
    return rc;
}

int taint_debug_numbers(int argc, char** argv)
{
    int infd = 0;
    struct taint_op top;
    long taint_ops = 0;
    struct stat buf;
    int rc;
    loff_t bytes_read = 0;
    int base = 2;

    char* group_dir;
    char taint_structures_filename[256];
    char results_filename[256];
    char filenames_filename[256];
    char tokens_filename[256];
    char debug_filename[256];

    if (argc < 3) {
        usage();
    }

    group_dir = argv[base];
    snprintf(taint_structures_filename, 256, "%s/node_nums", group_dir);
    snprintf(results_filename, 256, "%s/dataflow.result", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);
    snprintf(tokens_filename, 256, "%s/tokens", group_dir);
    snprintf(debug_filename, 256, "%s/trace_taint_ops", group_dir);

    merge_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    taint_operations_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    read_tokens(tokens_filename, option_info_table);
    read_filename_mappings(filenames_filename, filename_table);

    // read in the merge numbers
    read_merge_numbers(taint_structures_filename, merge_node_table);

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

int taint_debug(int argc, char** argv)
{
    int infd = 0;
    struct taint_op top;
    long taint_ops = 0;
    struct stat buf;
    int rc;
    loff_t bytes_read = 0;

    char* group_dir;
    char taint_structures_filename[256];
    char results_filename[256];
    char filenames_filename[256];
    char options_filename[256];
    char tokens_filename[256];
    char debug_filename[256];

    if (argc < 2) {
        usage();
    }

    group_dir = argv[1];
    snprintf(taint_structures_filename, 256, "%s/taint_structures", group_dir);
    snprintf(results_filename, 256, "%s/dataflow.result", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);
    snprintf(options_filename, 256, "%s/options", group_dir);
    snprintf(tokens_filename, 256, "%s/tokens", group_dir);
    snprintf(debug_filename, 256, "%s/trace_taint_ops", group_dir);

    leaf_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_index_table = g_hash_table_new(g_int64_hash, g_int64_equal);

    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    taint_operations_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    read_tokens(tokens_filename, option_info_table);
    read_filename_mappings(filenames_filename, filename_table);

    parse_taint_structures(taint_structures_filename,
                            leaf_node_table,
                            merge_node_table,
                            merge_index_table);


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
        bytes_read += read_taint_op_extended(infd, &top, 0);

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
    if (!strcmp(argv[1], "-n")) {
        return taint_debug_numbers(argc, argv);
    }
    return taint_debug(argc, argv);
}
