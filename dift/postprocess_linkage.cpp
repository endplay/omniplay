#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <glib-2.0/glib.h>
#include "taint_interface/taint.h"
#include "linkage_common.h"
#include "xray_slab_alloc.h"
#include "taint_interface/taint_creation.h"
#include "xray_token.h"
#include "maputil.h"

#include <unordered_set>
using namespace std;

int heartbleed = 0;
int xoutput = 0;
int taint_numbers = 0;

GHashTable* leaf_node_table = NULL;
GHashTable* merge_node_table = NULL;
GHashTable* merge_index_table = NULL;

GHashTable* filename_table = NULL;
GHashTable* option_info_table = NULL;

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

struct taint_entry {
    taint_t p1;
    taint_t p2;
};
struct taint_entry* merge_log = NULL;


int read_merge_numbers(char* taint_numbers_filename,
                        GHashTable* merge_node_table);

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
                            GHashTable* filename_table,
                            FILE* out_f)
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
            char* out_filename = (char *) "--";
            struct token* tok;
            struct taint_leafnode* ln = (struct taint_leafnode *) n;
            
            // lookup option number to metadata describing that option
            tok = (struct token *) g_hash_table_lookup(option_info_table, GINT_TO_POINTER(ln->option));
            assert(tok);

            // resolve filenames
            if (g_hash_table_contains(filename_table, GINT_TO_POINTER(tok->fileno))) {
                filename = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(tok->fileno));
            }
            if (g_hash_table_contains(filename_table, GINT_TO_POINTER(tci->fileno))) {
                out_filename = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(tci->fileno));
            }

            fprintf(out_f, "%s ", out_filename);
            fprintf(out_f, "%s ", filename);
            // Additional Stuff for oracle stuff
            fprintf(out_f, " %d %d %d",
                                tok->record_pid,
                                tok->syscall_cnt,
                                tok->byte_offset);
            fprintf(out_f, "\n");
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

void read_interpret_results(char* results_filename,
                                GHashTable* leaf_node_table,
                                GHashTable* merge_node_table,
                                GHashTable* option_info_table,
                                GHashTable* filename_table,
                                FILE* out_f)
{
    int fd;
    int rc;
    int bytes_read = 0;
    struct stat buf;
    fd = open(results_filename, O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "Could not open results file: %s, errno %d\n",
                        results_filename, errno);
        assert(0);
    }

    rc =  fstat(fd, &buf);
    if (rc) {
        fprintf(stderr, "Could not stat results file, errno %d\n", errno);
        assert(0);
    }

    while (bytes_read < buf.st_size) {
        struct taint_creation_info tci;
        u_long bufaddr;
        u_long buf_size;
        u_long i = 0;

        // read output header
        rc = read(fd, &tci, sizeof(struct taint_creation_info));
        if (rc != sizeof(struct taint_creation_info)) {
            fprintf(stderr, "expected to read taint_creation_info size %d, got %d, errno %d\n", sizeof(struct taint_creation_info), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        rc = read(fd, &bufaddr, sizeof(u_long));
        if (rc != sizeof(u_long)) {
            fprintf(stderr, "expected to read u_long bufaddr size %d, got %d, errno %d\n", sizeof(u_long), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        rc = read(fd, &buf_size, sizeof(u_long));
        if (rc != sizeof(u_long)) {
            fprintf(stderr, "expected to read u_long buf size %d, got %d, errno %d\n", sizeof(u_long), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        // now read the taints
        for (i = 0; i < buf_size; i++) {
            u_long addr;
            u_long value;

            rc = read(fd, &addr, sizeof(u_long));
            if (rc != sizeof(u_long)) {
                fprintf(stderr, "Could not read taint addr\n");
            }
            rc = read(fd, &value, sizeof(u_long));
            if (rc != sizeof(u_long)) {
                fprintf(stderr, "could not read taint value\n");
            }
            if (value) {
                print_leaf_options(&tci, value, i, leaf_node_table, merge_node_table, option_info_table, filename_table, out_f);
            } else {
                // fprintf(stdout, "0\n");
            }
        }
        bytes_read += (2* buf_size * sizeof(u_long));
    }
}

void print_taint_options(u_long taint,
                            u_long mem_loc,
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

    if (g_hash_table_contains(leaf_node_table, (gpointer) taint)) {
        new_addr = (u_long) g_hash_table_lookup(leaf_node_table, (gpointer) taint);
    } else {
        new_addr = (u_long) g_hash_table_lookup(merge_node_table, (gpointer) taint);
    }
    if (!new_addr) {
        fprintf(stderr, "Could not find taint: %lu\n", (u_long) taint);
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

            fprintf(stdout, "%lx: %llu %d %d %d %s",
                                mem_loc,
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


void parse_heartbleed_results(char* results_filename,
                                GHashTable* leaf_node_table,
                                GHashTable* merge_node_table,
                                GHashTable* option_info_table,
                                GHashTable* filename_table)
{
    int fd;
    int rc;
    int bytes_read = 0;
    struct stat buf;
    fd = open(results_filename, O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "Could not open results file: %s, errno %d\n",
                        results_filename, errno);
        assert(0);
    }

    rc =  fstat(fd, &buf);
    if (rc) {
        fprintf(stderr, "Could not stat results file, errno %d\n", errno);
        assert(0);
    }

    while (bytes_read < buf.st_size) {
        struct memcpy_header header;
        u_long i = 0;

        // read memcpy header
        rc = read(fd, &header, sizeof(struct memcpy_header));
        if (rc != sizeof(struct memcpy_header)) {
            fprintf(stderr, "expected to read memcpy_header size %d, got %d, errno %d\n", sizeof(struct memcpy_header), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        // now read the taints
        for (i = 0; i < header.len; i++) {
            u_long addr = header.dst + i;
            u_long value;

            rc = read(fd, &value, sizeof(u_long));
            if (rc != sizeof(u_long)) {
                fprintf(stderr, "could not read taint value\n");
            }
            if (value) {
                print_taint_options(value, addr,
                                        leaf_node_table,
                                        merge_node_table,
                                        option_info_table,
                                        filename_table);
            } else {
                // fprintf(stdout, "%lx 0\n", addr);
            }
            bytes_read += rc;
        }
    }
}

void print_xtaint_options(u_long taint,
                            int dest_x, int dest_y,
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

    if (g_hash_table_contains(leaf_node_table, (gpointer) taint)) {
        new_addr = (u_long) g_hash_table_lookup(leaf_node_table, (gpointer) taint);
    } else {
        new_addr = (u_long) g_hash_table_lookup(merge_node_table, (gpointer) taint);
    }
    if (!new_addr) {
        fprintf(stderr, "Could not find taint: %lu\n", (u_long) taint);
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

            fprintf(stdout, "(%d,%d): %llu %d %d %d %s",
                                dest_x,
                                dest_y,
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

void print_merge_number_xtaint_options(u_long taint_number,
                                int dest_x,
                                int dest_y,
                                GHashTable* leaf_node_table,
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

            fprintf(stdout, "(%d,%d): %llu %d %d %d %s",
                                dest_x,
                                dest_y,
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


void parse_xoutput_results(char* results_filename,
                                GHashTable* leaf_node_table,
                                GHashTable* merge_node_table,
                                GHashTable* option_info_table,
                                GHashTable* filename_table,
                                int merge_numbers)
{
    int fd;
    int rc;
    int bytes_read = 0;
    struct stat buf;
    fd = open(results_filename, O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "Could not open results file: %s, errno %d\n",
                        results_filename, errno);
        assert(0);
    }

    rc =  fstat(fd, &buf);
    if (rc) {
        fprintf(stderr, "Could not stat results file, errno %d\n", errno);
        assert(0);
    }

    while (bytes_read < buf.st_size) {
        int syscall_cnt;
        int dest_x;
        int dest_y;
        u_long value;

        rc = read(fd, &syscall_cnt, sizeof(syscall_cnt));
        if (rc != sizeof(syscall_cnt)) {
            assert(0);
        }
        bytes_read += rc;

        rc = read(fd, &dest_x, sizeof(dest_x));
        if (rc != sizeof(dest_x)) {
            assert(0);
        }
        bytes_read += rc;

        rc = read(fd, &dest_y, sizeof(dest_y));
        if (rc != sizeof(dest_y)) {
            assert(0);
        }
        bytes_read += rc;

        // read the taint
        rc = read(fd, &value, sizeof(u_long));
        if (rc != sizeof(u_long)) {
            fprintf(stderr, "could not read taint value\n");
        }
        bytes_read += rc;
        if (value) {
            if (!taint_numbers) {
                print_xtaint_options(value, dest_x, dest_y,
                                        leaf_node_table,
                                        merge_node_table,
                                        option_info_table,
                                        filename_table);
            } else {
                print_merge_number_xtaint_options(value, dest_x, dest_y,
                                        leaf_node_table,
                                        merge_node_table,
                                        option_info_table,
                                        filename_table);
            }
        }
    }
}


void usage()
{
    printf("Usage: ./postprocess_linkage <directory>\n");
}

int append_files(char* file1, char* file2, int pid) {
    FILE* fp1; 
    FILE* fp2;
    FILE* out_f;
    off_t f_size1, f_size2;
    char* buffer1;
    char* buffer2;
    struct stat sb;

    // Out File
    char out_filename[256];
    snprintf(out_filename, 256, "/tmp/%d/%d", pid, pid);
    out_f = fopen(out_filename, "w");
    if (!out_f) {fprintf(stderr, "error opening output file\n"); return 0;}

    // Read First File
    if (stat(file1,  &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    f_size1 = sb.st_size;
    fp1 = fopen(file1, "r");
    if (!fp1) {fprintf(stderr, "error opening file %s\n", file1); return 0;}
    
    buffer1 = (char*)malloc(sizeof(char) * (f_size1));
    if (!buffer1) {fprintf(stderr, "error creating buffer\n"); return 0;}
    fseek(fp1, 0, SEEK_SET);
    if (fread(buffer1, 1, f_size1, fp1) != 1) {
      printf ("fread returns value other than 1\n");
    }

    // Write First File
    off_t result = fwrite(buffer1, 1, f_size1, out_f);
    if (result != f_size1) {
        perror("fwrite");
        exit(EXIT_FAILURE);
    }

    // Read Second File
    if (stat(file2,  &sb) == -1) {
        perror("lstat");
        exit(EXIT_FAILURE);
    }
    f_size2 = sb.st_size;
    fp2 = fopen(file2, "r");
    if (!fp2) {fprintf(stderr, "error opening file %s\n", file2); return 0;}
    
    buffer2 = (char*)malloc(sizeof(char) * (f_size2));
    if (!buffer2) {fprintf(stderr, "error creating buffer\n"); return 0;}
    fseek(fp2, 0, SEEK_SET);
    if ((off_t) fread(buffer2, 1, f_size2, fp2) != f_size2) {
        perror("fread");
        exit(EXIT_FAILURE);
    }
 
    // Write Second File
    result = fwrite(buffer2, 1, f_size2, out_f);
    if (result != f_size2) {
        perror("fwrite");
        exit(EXIT_FAILURE);
    }

   /*
    int buf_size = 1<<16;
    int total_read = 0;

    buffer2 = malloc(buf_size);
    if (!buffer2) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    while (!feof(fp2)) {
        size_t nread;
        size_t nwritten;
        nread = fread(buffer2, 1, buf_size, fp2);
        if (nread < 0) {
            perror("fread");
            exit(EXIT_FAILURE);
        }
        total_read += nread;

        nwritten = fwrite(buffer2, 1, nread, out_f);
        if (nwritten != nread) {
            perror("fwrite");
            exit(EXIT_FAILURE);
        }
    }
    fprintf(stderr, "total_read is %d\n", total_read);
    */
    return 1;
}


int read_backwards_results(int argc, char** argv)
{
    int base = 1;
    //char group_dir[256];
    char* group_dir;
    char taint_structures_filename[256];
    char results_filename[256];
    char filenames_filename[256];
    char tokens_filename[256];
    int pid;
    int append = 0;

    if (argc < 2) {
        usage();
    }

    if (!strcmp(argv[base], "-o")) {
        append = 1;
        base++;
    }
    //snprintf(group_dir, 256, "/tmp/%s", argv[base]);
    group_dir = argv[base];
    //snprintf(taint_structures_filename, 256, "%s/taint_structures_%s", group_dir, argv[base]);
    snprintf(taint_structures_filename, 256, "%s/taint_structures", group_dir);
    snprintf(results_filename, 256, "%s/dataflow.result", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);
    snprintf(tokens_filename, 256, "%s/tokens", group_dir);

    // adding 5 to group_dir to remove '/tmp/'
    pid = atoi(group_dir+5);

    FILE* out_f;
    char out_filename[40];
    snprintf(out_filename, 40, "/tmp/%d/out", pid);
    out_f = fopen(out_filename, "w");
    if(!out_f) {
        fprintf(stderr, "couldn't open %s\n", out_filename);
        return -1;
    }

    leaf_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_index_table = g_hash_table_new(g_int64_hash, g_int64_equal);

    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    read_tokens(tokens_filename, option_info_table);
    read_filename_mappings(filenames_filename, filename_table);

    parse_taint_structures(taint_structures_filename,
                            leaf_node_table,
                            merge_node_table,
                            merge_index_table);

    // print_leaf_options(2949968896, leaf_node_table, merge_node_table);
    read_interpret_results(results_filename,
                            leaf_node_table,
                            merge_node_table,
                            option_info_table,
                            filename_table,
                            out_f);
    fflush(out_f);
    if (append) {
        char opened_filename[256];
        snprintf(opened_filename, 256, "%s/opened_files", group_dir);
        if(!append_files(opened_filename, out_filename, pid)){
            fprintf(stderr, "problem appending\n");
        }
    }
    return 0;
}

void print_forward_options(struct taint_creation_info* tci,
                                                GHashTable* filename_table,
                                                u_long buf,
                                                u_long buf_size,
                                                u_long new_bufaddr,
                                                u_long new_buf_size,
                                                uint8_t* taints)
{
    int i = 0;
    int start = 0;
    int end = 0;
    assert(new_bufaddr <= buf);
    assert(new_buf_size >= buf_size);
    start = new_bufaddr - buf;
    end = buf_size;
    // TODO for now just print out extra
    for (i = start; i < end; i++) {
        int idx = (i - start) / 8;
        int bitfield = 0x1 << (i % 8);
        if (taints[idx] & bitfield) {
            char* out_filename = (char *) "--";
            if (g_hash_table_contains(filename_table, GINT_TO_POINTER(tci->fileno))) {
                out_filename = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(tci->fileno));
            }
            fprintf(stdout, "%llu %d %lu %d %s\n",
                                tci->rg_id,
                                tci->record_pid,
                                tci->syscall_cnt,
                                i,
                                out_filename);
        }
    }
}

void interpret_forward_results(char* results_filename, GHashTable* filename_table)
{
    int fd;
    int rc;
    int bytes_read = 0;
    struct stat buf;
    fd = open(results_filename, O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "Could not open results file: %s, errno %d\n",
                        results_filename, errno);
        assert(0);
    }

    rc =  fstat(fd, &buf);
    if (rc) {
        fprintf(stderr, "Could not stat results file, errno %d\n", errno);
        assert(0);
    }

    while (bytes_read < buf.st_size) {
        struct taint_creation_info tci;
        u_long bufaddr;
        u_long buf_size;
        u_long new_buf_size;
        u_long new_bufaddr;
        uint8_t* taints;

        // read output header
        rc = read(fd, &tci, sizeof(struct taint_creation_info));
        if (rc != sizeof(struct taint_creation_info)) {
            fprintf(stderr, "expected to read taint_creation_info size %d, got %d, errno %d\n", sizeof(struct taint_creation_info), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        rc = read(fd, &bufaddr, sizeof(u_long));
        if (rc != sizeof(u_long)) {
            fprintf(stderr, "expected to read u_long bufaddr size %d, got %d, errno %d\n", sizeof(u_long), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        rc = read(fd, &buf_size, sizeof(u_long));
        if (rc != sizeof(u_long)) {
            fprintf(stderr, "expected to read u_long buf size %d, got %d, errno %d\n", sizeof(u_long), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        // round down to nearest factor of 8
        new_buf_size = (bufaddr % 8);
        new_bufaddr = bufaddr - (bufaddr % 8);
        // round up bufsize to nearest factor of 8
        new_buf_size += buf_size;
        if ((new_bufaddr + new_buf_size) % 8) {
            new_buf_size += (8 - ((new_bufaddr + new_buf_size) % 8));
        }
        if (new_buf_size % 8 != 0) {
            fprintf(stderr, "buf_size %lu, new_buf_size: %lu\n", buf_size, new_buf_size);
        }
        assert(new_buf_size % 8 == 0);
        fprintf(stderr, "new_buf_size %ld\n", new_buf_size);

        // now read the taints
        taints = (uint8_t *) malloc(sizeof(uint8_t) * (new_buf_size / 8));
        rc = read(fd, taints, (sizeof(uint8_t) * (new_buf_size / 8)));
        if (rc != (sizeof(uint8_t) * (new_buf_size / 8))) {
            fprintf(stderr, "Could not read tainted buffer\n");
            assert(0);
        }
        print_forward_options(&tci, filename_table, bufaddr, buf_size, 
                new_bufaddr, new_buf_size, taints);
        bytes_read += rc;
    }
}

int read_forwards_results(int argc, char** argv)
{
    char* group_dir;
    char results_filename[256];
    char filenames_filename[256];

    if (argc < 3) {
        usage();
    }

    group_dir = argv[2];
    snprintf(results_filename, 256, "%s/dataflow.result", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);

    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    read_filename_mappings(filenames_filename, filename_table);

    interpret_forward_results(results_filename, filename_table);

    return 0;
}

int read_heartbleed_results(int argc, char** argv)
{
    char* group_dir;
    char taint_structures_filename[256];
    char results_filename[256];
    char filenames_filename[256];
    char tokens_filename[256];

    if (argc < 2) {
        usage();
    }

    group_dir = argv[1];
    snprintf(taint_structures_filename, 256, "%s/taint_structures", group_dir);
    snprintf(results_filename, 256, "%s/heartbleed.result", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);
    snprintf(tokens_filename, 256, "%s/tokens", group_dir);

    leaf_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_index_table = g_hash_table_new(g_int64_hash, g_int64_equal);

    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    read_tokens(tokens_filename, option_info_table);
    read_filename_mappings(filenames_filename, filename_table);

    parse_taint_structures(taint_structures_filename,
                            leaf_node_table,
                            merge_node_table,
                            merge_index_table);

    // print_leaf_options(2949968896, leaf_node_table, merge_node_table);
    parse_heartbleed_results(results_filename,
                            leaf_node_table,
                            merge_node_table,
                            option_info_table,
                            filename_table);

    return 0;
}

int read_xoutput_results(int argc, char** argv)
{
    int base = 2;
    char* group_dir;
    char taint_structures_filename[256];
    char results_filename[256];
    char filenames_filename[256];
    char tokens_filename[256];

    if (argc < 3) {
        usage();
    }

    if (!strcmp(argv[base], "-n")) {
        taint_numbers = 1;
        base++;
    }
    group_dir = argv[base];
    snprintf(results_filename, 256, "%s/xoutput.result", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);
    snprintf(tokens_filename, 256, "%s/tokens", group_dir);

    leaf_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_index_table = g_hash_table_new(g_int64_hash, g_int64_equal);

    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    read_tokens(tokens_filename, option_info_table);
    read_filename_mappings(filenames_filename, filename_table);

    if (!taint_numbers) {
        snprintf(taint_structures_filename, 256, "%s/taint_structures", group_dir);
        parse_taint_structures(taint_structures_filename,
                leaf_node_table,
                merge_node_table,
                merge_index_table);
        parse_xoutput_results(results_filename,
                            leaf_node_table,
                            merge_node_table,
                            option_info_table,
                            filename_table,
                            taint_numbers);
    } else {
        snprintf(taint_structures_filename, 256, "%s/node_nums", group_dir);
        read_merge_numbers(taint_structures_filename, merge_node_table);
        parse_xoutput_results(results_filename,
                            leaf_node_table,
                            merge_node_table,
                            option_info_table,
                            filename_table,
                            taint_numbers);
    }

    // print_leaf_options(2949968896, leaf_node_table, merge_node_table);

    return 0;
}

int read_merge_numbers(char* taint_numbers_filename,
                        GHashTable* merge_node_table)
{
    struct stat buf;
    int fd;
    int rc;

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

    if (buf.st_size % 4096) buf.st_size += 4096 - (buf.st_size % 4096);
    merge_log = (taint_entry *) mmap (NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (merge_log == MAP_FAILED) {
	perror ("mmap");
	rc = -1;
    } else {
	rc = 0;
    }

    close(fd);
    return rc;
}

void print_merge_number_options(struct taint_creation_info* tci,
                                u_long taint_number,
                                int output_byte_offset,
                                GHashTable* merge_node_table,
                                GHashTable* option_info_table,
                                GHashTable* filename_table,
                                FILE* out_f)
{
    GHashTable* seen_indices;
    GQueue* queue;
    struct taint_entry* pentry;

    seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    queue = g_queue_new();

    assert(taint_number);
    assert(tci);

    g_queue_push_tail(queue, GUINT_TO_POINTER(taint_number));
    while(!g_queue_is_empty(queue)) {

        u_long n = GPOINTER_TO_UINT(g_queue_pop_head(queue));
        assert(n);
	if (g_hash_table_contains(seen_indices, GUINT_TO_POINTER(n))) {
	    continue;
	}
	g_hash_table_add(seen_indices, GUINT_TO_POINTER(n));

	if (n <= 0xe0000000) {
		struct token* tok;
		// lookup option number to metadata describing that option
		tok = (struct token *) g_hash_table_lookup(option_info_table, GINT_TO_POINTER(n));
		assert(tok);
		
#ifdef USE_FILENAMES
		char* filename = (char *) "--";
		char* out_filename = (char *) "--";
		// resolve filenames
		if (g_hash_table_contains(filename_table, GINT_TO_POINTER(tok->fileno))) {
		    filename = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(tok->fileno));
		}
		if (g_hash_table_contains(filename_table, GINT_TO_POINTER(tci->fileno))) {
		    out_filename = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(tci->fileno));
		}

		fprintf(stdout, "%llu %d %lu %d %s ",    
			tci->rg_id,
			tci->record_pid,
			tci->syscall_cnt,
			output_byte_offset,
			out_filename);
		fprintf(stdout, "%llu %d %d %d %s",
			tok->rg_id,
			tok->record_pid,
			tok->syscall_cnt,
			tok->byte_offset,
			filename);
#else
		fprintf(stdout, "%llu %d %lu %d ",    
			tci->rg_id,
			tci->record_pid,
			tci->syscall_cnt,
			output_byte_offset);
		fprintf(stdout, "%llu %d %d %d",
			tok->rg_id,
			tok->record_pid,
			tok->syscall_cnt,
			tok->byte_offset);
#endif
		fprintf(stdout, "\n");
        } else {
	    pentry = &merge_log[n-0xe0000001];
	    //fprintf (stdout, "%lx -> %lx, %lx\n", n, pentry->p1, pentry->p2);
	    g_queue_push_tail(queue, GUINT_TO_POINTER(pentry->p1));
	    g_queue_push_tail(queue, GUINT_TO_POINTER(pentry->p2));
        }
    }
    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
}

int parse_merge_numbers(char* results_filename,
                            GHashTable* merge_node_table,
                            GHashTable* option_info_table,
                            GHashTable* filename_table,
                            FILE* out_f)
{
    int fd;
    int rc;
    int bytes_read = 0;
    struct stat buf;
    fd = open(results_filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "could not open results file: %s, errno %d\n",
                results_filename, errno);
        return errno;
    }

    rc = fstat(fd, &buf);
    if (rc) {
        fprintf(stderr, "could not stat results file, errno %d\n", errno);
        return errno;
    }

    while (bytes_read < buf.st_size) {
        struct taint_creation_info tci;
        u_long bufaddr;
        u_long buf_size;
        u_long i = 0;

        // read output header
        rc = read(fd, &tci, sizeof(struct taint_creation_info));
        if (rc != sizeof(struct taint_creation_info)) {
            fprintf(stderr, "expected to read taint_creation_info size %d, got %d, errno %d\n", sizeof(struct taint_creation_info), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        rc = read(fd, &bufaddr, sizeof(u_long));
        if (rc != sizeof(u_long)) {
            fprintf(stderr, "expected to read u_long bufaddr size %d, got %d, errno %d\n", sizeof(u_long), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        rc = read(fd, &buf_size, sizeof(u_long));
        if (rc != sizeof(u_long)) {
            fprintf(stderr, "expected to read u_long buf size %d, got %d, errno %d\n", sizeof(u_long), rc, errno);
            assert(0);
        }
        bytes_read += rc;

        // now read the taints
        for (i = 0; i < buf_size; i++) {
            u_long addr;
            u_long value;

            rc = read(fd, &addr, sizeof(u_long));
            if (rc != sizeof(u_long)) {
                fprintf(stderr, "Could not read taint addr\n");
            }
            rc = read(fd, &value, sizeof(u_long));
            if (rc != sizeof(u_long)) {
                fprintf(stderr, "could not read taint value\n");
            }
            if (value) {
                print_merge_number_options(&tci, value, i, merge_node_table,
                                            option_info_table, filename_table,
                                            out_f);
            } else {
                // fprintf(stdout, "0\n");
            }
        }
        bytes_read += (2* buf_size * sizeof(u_long));

    }
    return 0;
}

int read_backwards_merge_numbers(int argc, char** argv)
{
    int base = 2;
    char* group_dir;
    char taint_structures_filename[256];
    char results_filename[256];
    char filenames_filename[256];
    char tokens_filename[256];
    int pid;

    if (argc < 2) {
        usage();
    }

    if (!strcmp(argv[base], "-o")) {
        base++;
    }

    group_dir = argv[base];
    snprintf(taint_structures_filename, 256, "%s/node_nums", group_dir);
    snprintf(results_filename, 256, "%s/dataflow.result", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);
    snprintf(tokens_filename, 256, "%s/tokens", group_dir);

    // adding 5 to group_dir to remove '/tmp/'
    pid = atoi(group_dir+5); 

    FILE* out_f;
    char out_filename[40];
    snprintf(out_filename, 40, "/tmp/%d/out", pid);
    out_f = fopen(out_filename, "w");
    if(!out_f) {
        fprintf(stderr, "couldn't open %s\n", out_filename);
        return -1;
    }

    // merge_node_table is a mapping of taint number to struct taint number
    merge_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    read_tokens(tokens_filename, option_info_table);
    read_filename_mappings(filenames_filename, filename_table);

    // read in the merge numbers
    read_merge_numbers(taint_structures_filename, merge_node_table);

    parse_merge_numbers(results_filename, merge_node_table,
                        option_info_table, filename_table,
                        out_f);
    return 0;
}

#ifdef STATS
static u_long merges = 0;
static u_long indirects = 0;
static u_long directs = 0;
#endif

#define OUTBUFSIZE 1000000
u_long outbuf[OUTBUFSIZE];
u_long outindex = 0;
int outfd;

static void flush_outbuf()
{
    long bytes_written = 0;
    long size = outindex*sizeof(u_long);

    while (bytes_written < size) {
	long rc = write (outfd, (char *) outbuf+bytes_written, size-bytes_written);	
	if (rc <= 0) {
	    fprintf (stderr, "pp: write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	    exit (rc);
	}
	bytes_written += rc;
    }
    outindex = 0;
}

static inline void print_relation (u_long value) 
{
    if (outindex == OUTBUFSIZE) flush_outbuf();
    outbuf[outindex++] = value;
}

static inline void print_sentinal ()
{
    if (outindex == OUTBUFSIZE) flush_outbuf();
    outbuf[outindex++] = 0;
}

#define STACK_SIZE 1000000

static void print_merge (taint_t value)
{
    struct taint_entry* pentry;
    unordered_set<taint_t> seen_indices;
    taint_t stack[STACK_SIZE];
    u_long stack_depth = 0;

    pentry = &merge_log[value-0xe0000001];
    stack[stack_depth++] = pentry->p1;
    stack[stack_depth++] = pentry->p2;

    do {
	value = stack[--stack_depth];

	if (seen_indices.insert(value).second) {
	    if (value <= 0xe0000000) {
		print_relation (value);
	    } else {
#ifdef STATS
		merges++;
#endif
		pentry = &merge_log[value-0xe0000001];
		stack[stack_depth++] = pentry->p1;
		stack[stack_depth++] = pentry->p2;
		assert (stack_depth < STACK_SIZE);
	    }
	}
    } while (stack_depth);
}

int map_shmem (char* filename, int* pfd, u_long* pdatasize, u_long* pmapsize, char** pbuf)
{
    char shmemname[256];
    struct stat st;
    u_long size;
    int fd, rc;
    u_long i;
    char* buf;

    snprintf(shmemname, 256, "/node_nums_shm%s", filename);
    for (i = 1; i < strlen(shmemname); i++) {
	if (shmemname[i] == '/') shmemname[i] = '.';
    }
    shmemname[strlen(shmemname)-10] = '\0';
    fd = shm_open (shmemname, O_RDONLY, 0);
    if (fd < 0) {
	fprintf (stderr, "Unable to open %s, rc=%d, errno=%d\n", shmemname, fd, errno);
	return fd;
    }
    rc = fstat(fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Unable to stat %s, rc=%d, errno=%d\n", shmemname, rc, errno);
	return rc;
    }
    if (st.st_size%4096) {
	size = st.st_size + 4096-st.st_size%4096;
    } else {
	size = st.st_size;
    }
    buf = (char *) mmap (NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buf == MAP_FAILED) {
	fprintf (stderr, "Cannot map file %s, errno=%d\n", shmemname, errno);
	return -1;
    }

    // This is the last process to use the merge region
    // This will deallocate it  after we exit
//    rc = shm_unlink (shmemname); 
//    if (rc < 0) perror ("shmem_unlink");

    *pfd = fd;
    *pdatasize = st.st_size;
    *pmapsize = size;
    *pbuf = buf;

    return 0;
}

int parse_merge (char* results_filename, GHashTable* merge_node_table)
{
    int fd, rc;
    u_long outsize, mapsize;
    char* buf, *pout;
    taint_t value;
    u_long buf_size;

    rc = map_file (results_filename, &fd, &outsize, &mapsize, &buf);
    if (rc < 0) return rc;

    pout = buf;
    while (pout < buf + outsize) {

	pout += sizeof(struct taint_creation_info);
	pout += sizeof(u_long);
	buf_size = *((u_long *) pout);
	pout += sizeof(u_long);

        // now read the taints
        for (u_long i = 0; i < buf_size; i++) {

	    pout += sizeof(u_long);
	    value = *((u_long *) pout);
#ifdef DEBUGTRACE_OUTPUT
	    if (output_cnt == DEBUGTRACE_OUTPUT) {
		printf ("output token %lx value %lx\n", output_cnt, value);
	    }
#endif	    
            if (value) {
		if (value < 0xe0000000)  {
#ifdef STATS
		    directs++;
#endif
		    print_relation(value);
		} else {
#ifdef STATS
		    indirects++;
		    merges++;
#endif
		    print_merge (value);
		}
            }
#ifdef DEBUGTRACE_OUTPUT
	    output_cnt++;
#endif
	    pout += sizeof(taint_t);
	    print_sentinal();
        }

    }
    flush_outbuf();

    return 0;
}

int read_merge (char* group_dir, char* pid)
{
    char taint_structures_filename[256];
    char results_filename[256];
    char out_filename[256];
    u_long moutsize, mmapsize;
    int mfd, rc;
    
    /*
     * If we are running the code for a specific pid than the output and the 
     * dataflow.results filenames are different. However, the shared memory 
     * needs to be handled the same regardless as to whether a pid is
     * specified.
    */

    if(pid == NULL) 
    {
	snprintf(results_filename, 256, "%s/dataflow.result", group_dir);
	snprintf (out_filename, 256, "%s/mergeout", group_dir);
    }
    else 
    {
	snprintf(results_filename, 256, "%s/dataflow.result.%s", group_dir, pid);
	snprintf (out_filename, 256, "%s/mergeout.%s", group_dir, pid);
    }

    snprintf(taint_structures_filename, 256, "%s/node_nums", group_dir);
    outfd = open (out_filename, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (outfd < 0) {
        fprintf(stderr, "couldn't open: %s\n", out_filename);
        return outfd;
    }
	
    // merge_node_table is a mapping of taint number to struct taint number
    merge_node_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    rc = map_shmem (taint_structures_filename, &mfd, &moutsize, &mmapsize, (char **) &merge_log);
    if (rc < 0) return rc;

    parse_merge(results_filename, merge_node_table);

#ifdef STATS
    printf ("directs %lu, inedirects %lu, merges %lu\n", directs, indirects, merges);
#endif
    return 0;
}


int main(int argc, char** argv)
{
    char *group_dir = NULL, *pid=NULL, opt;

    while (1) 
    {
	opt = getopt(argc, argv, "fxlnm:p:");
//	printf("getopt returns %c (%d)\n", opt, opt);

	if (opt == -1) 
	{
	    break;
	}
	switch(opt) 
	{
	case 'f':
	    return read_forwards_results(argc,argv);
	case 'x':
	    return read_xoutput_results(argc,argv);
	case 'l':
	    return read_heartbleed_results(argc,argv);
	case 'n':
	    return read_backwards_merge_numbers(argc,argv);
	case 'm':
	    group_dir = optarg;
	    break;
	case 'p': 
	    pid = optarg;
	    break;
	default:
	    fprintf(stderr, "Unrecognized option\n");
	    break;
	}
    }
    if(group_dir != NULL)
    {
	return read_merge(group_dir, pid);
    }
    return read_backwards_results(argc,argv);
}

