#include "../linkage_common.h"
#include "taint_interface.h"
#include <string.h>
#include <assert.h>
#include <glib-2.0/glib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#define USE_MERGE_HASH
#define TAINT_STATS

extern struct thread_data* current_thread;
extern int splice_output;

#define FIRST_TABLE_SIZE 131072
#define SECOND_TABLE_SIZE 1024
#define THIRD_TABLE_SIZE 32

#define FIRST_TABLE_BITS 17
#define SECOND_TABLE_BITS 10
#define THIRD_TABLE_BITS 5

#define MID_INDEX_MASK 0x000003FF
#define LOW_INDEX_MASK 0x0000001F
#define MIDHIGH_INDEX_MASK 0xFFFFFFE0
#define DIRECT_MASK 0x00000001

// #define HIGH_SHIFTPOS   (1 << (SECOND_TABLE_BITS + THIRD_TABLE_BITS))
#define HIGH_SHIFTPOS   0x8000
// #define HIGH_SHIFTMASK  HIGH_SHIFTPOS - 1
#define HIGH_SHIFTMASK  0x7fff

// #define LOGGING_ON
#ifdef LOGGING_ON
#define TAINT_START(name) \
    fprintf(stderr, "%s start\n", name);
#else
#define TAINT_START(x,...);
#endif

void* mem_loc_high[FIRST_TABLE_SIZE];  // Top-level table for memory taints

// File-descriptor tainting
// A mapping of open fds to taint values.
// We do this mapping manually because some system calls, like select use a bitmap to
// track sets of fds. Our fidelty of taint-tracking, however, doesn't extend to bit
// levels.
GHashTable* taint_fds_table = NULL;
GHashTable* taint_fds_cloexec = NULL;

#ifdef TAINT_STATS
struct taint_stats_profile {
    unsigned long num_second_tables;
    unsigned long num_third_tables;
    unsigned long merges;
    unsigned long merges_saved;
    unsigned long options;
};
struct taint_stats_profile tsp;
#endif

#include "../xray_slab_alloc.h"
struct slab_alloc second_table_alloc;
struct slab_alloc third_table_alloc;
struct slab_alloc leaf_alloc;
struct slab_alloc node_alloc;
struct slab_alloc uint_alloc;

// use taint numbers instead
taint_t taint_num;
int node_num_fd = -1;

// Strategy for merge log is to put the first n bytes in named shared memory (fast)
// If this is too small, use an on-disk file for the overlow data (slow)
struct taint_number {
    taint_t p1;
    taint_t p2;
};

extern u_long num_merge_entries;
#define MERGE_BLOCK_SIZE (num_merge_entries*sizeof(struct taint_number))
#define MERGE_FILE_ENTRIES 0x100000
#define MERGE_FILE_CHUNK (MERGE_FILE_ENTRIES*sizeof(struct taint_number))

static struct taint_number* merge_buffer;
static bool merge_buf_overflow = false;
static u_long merge_buffer_count = 0;
taint_t merge_total_count = 0xe0000001;
static char node_num_filename[256];

#ifdef DEBUGTRACE

GHashTable* trace_set = NULL;

static void init_trace_set ()
{
    if (trace_set == NULL) {
	trace_set = g_hash_table_new (NULL, NULL);
	g_hash_table_add (trace_set, GUINT_TO_POINTER(DEBUGTRACE));
    }
}

void add_to_trace_set(u_long val)
{
    init_trace_set();
    g_hash_table_add (trace_set, GUINT_TO_POINTER(val));
}

int is_in_trace_set(u_long val) 
{
    init_trace_set();
    return g_hash_table_contains (trace_set, GUINT_TO_POINTER(val));
}
#endif

static void 
flush_merge_buffer ()
{
    long bytes_written = 0;
    long size = num_merge_entries*sizeof(struct taint_number);
    
    while (bytes_written < size) {
	long rc = write (node_num_fd, (char *) merge_buffer+bytes_written, size-bytes_written);	
	if (rc <= 0) {
	    fprintf (stderr, "Canot write to merge log, rc=%ld\n", rc);
	    assert (0);
	}
	bytes_written += rc;
    }
}

static taint_t 
add_merge_number(taint_t p1, taint_t p2)
{
    if (merge_buffer_count == num_merge_entries) {
	if (!merge_buf_overflow) {

	    // Need to close the shmem and open the overflow file
	    if (munmap (merge_buffer, MERGE_BLOCK_SIZE) < 0) {
		fprintf (stderr, "could not munmap merge buffer, errno=%d\n", errno);
		assert (0);
	    }
	    close (node_num_fd);

	    node_num_fd = open(node_num_filename, O_CREAT | O_TRUNC | O_RDWR | O_LARGEFILE, 0644);
	    if (node_num_fd < 0) {
		fprintf(stderr, "could not open node num file %s, errno %d\n",
			node_num_filename, errno);
		assert(0);
	    }

	    merge_buffer = (struct taint_number *) malloc(MERGE_FILE_CHUNK);
	    if (merge_buffer == NULL) {
		fprintf (stderr, "Cannnot allocate file write buffer\n");
		assert (0);
	    }
	    num_merge_entries = MERGE_FILE_ENTRIES;
	    merge_buf_overflow = true;
	} else {
	    flush_merge_buffer();
	}
	merge_buffer_count = 0;
    } 
    merge_buffer[merge_buffer_count].p1 = p1;
    merge_buffer[merge_buffer_count].p2 = p2;
#ifdef DEBUGTRACE
    if (is_in_trace_set (p1) || is_in_trace_set (p2)) {
	printf ("merge: %lx, %lx -> %lx\n", p1, p2, merge_total_count);
	add_to_trace_set (merge_total_count);
    }
#endif
    merge_buffer_count++;
    return merge_total_count++;
}

struct taint_node {
    struct taint_node* parent1;
    struct taint_node* parent2;
};

struct taint_leafnode {
    struct taint_node node;
    option_t option;
};


#ifdef USE_MERGE_HASH

// simple hash for holding merged indices
#define SIMPLE_HASH_SIZE 0x100000
struct simple_bucket {
    taint_t p1, p2, n;
};
struct simple_bucket simple_hash[SIMPLE_HASH_SIZE];

#endif

#ifdef TAINT_STRUCTS_WRITEOUT
int leaf_fd = -1;
int node_fd = -1;
#endif

// #define TAINT_FULL_DEBUG
#ifdef TAINT_FULL_DEBUG
GHashTable* leaf_node_addrs = NULL;
GHashTable* merge_node_addrs = NULL;
void assert_valid_taint_addr(taint_t t)
{

    if (!((g_hash_table_contains(leaf_node_addrs, (gpointer) t) ||
            g_hash_table_contains(merge_node_addrs, (gpointer) t)) || (t == 0))) {
        fprintf(stderr, "invalid taint is %lu\n", t);
    }
    assert((g_hash_table_contains(leaf_node_addrs, (gpointer) t) ||
            g_hash_table_contains(merge_node_addrs, (gpointer) t)) || (t == 0));
}

int check_valid_taint_addr(taint_t t)
{

    if (!((g_hash_table_contains(leaf_node_addrs, (gpointer) t) ||
            g_hash_table_contains(merge_node_addrs, (gpointer) t)) || (t == 0))) {
        fprintf(stderr, "invalid taint is %lu\n", t);
    }
    return ((g_hash_table_contains(leaf_node_addrs, (gpointer) t) ||
            g_hash_table_contains(merge_node_addrs, (gpointer) t)) || (t == 0));
}


void check_reg_taints(int reg)
{
    int i = 0;
    for (i = 0; i < REG_SIZE; i++) {
        if (!check_valid_taint_addr(current_thread->shadow_reg_table[reg * REG_SIZE + i])) {
            fprintf(stderr, "found invalid taint in reg %d[%d]\n", reg, i);
            assert(0);
        }
    }
}

void check_mem_taints(taint_t* mem_taints, u_long addr, int size)
{
    int i = 0;
    assert(mem_taints);
    for (i = 0; i < size; i++) {
        if (!check_valid_taint_addr(mem_taints[i])) {
            fprintf(stderr, "found invalid taint at mem addr %#lx\n", addr + i);
            assert(0);
        }
    }
}
#endif

static inline void init_taint_index(char* group_dir)
{
#ifdef USE_MERGE_HASH
    memset(&simple_hash,0,sizeof(simple_hash));
#endif
#ifdef TAINT_STATS
    memset(&tsp, 0, sizeof(tsp));
#endif
    init_slab_allocs();
    {
        char node_num_shmemname[256];
	int rc;
	u_int i;

        snprintf(node_num_shmemname, 256, "/node_nums_shm%s", group_dir);
	for (i = 1; i < strlen(node_num_shmemname); i++) {
	    if (node_num_shmemname[i] == '/') node_num_shmemname[i] = '.';
	}
        snprintf(node_num_filename, 256, "%s/node_nums", group_dir);
        node_num_fd = shm_open(node_num_shmemname, O_CREAT | O_TRUNC | O_RDWR, 0644);
        if (node_num_fd < 0) {
            fprintf(stderr, "could not open node num shmem %s, errno %d\n",
		    node_num_shmemname, errno);
            assert(0);
        }
	rc = ftruncate (node_num_fd, MERGE_BLOCK_SIZE);
	if (rc < 0) {
            fprintf(stderr, "could not truncate shmem %s, errno %d\n",
		    node_num_shmemname, errno);
            assert(0);
        }
	merge_buffer = (struct taint_number *) mmap (0, MERGE_BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, 
						     node_num_fd, 0);
	if (merge_buffer == MAP_FAILED) {
	    fprintf (stderr, "could not map merge buffer, errno=%d\n", errno);
	    assert (0);
	}
    }

    //new_slab_alloc((char *)"UINT_ALLOC", &uint_alloc, sizeof(guint64), 2000000);
    new_slab_alloc((char *)"UINT_ALLOC", &uint_alloc, sizeof(guint64), 4000000);
    new_slab_alloc((char *)"2TABLE_ALLOC", &second_table_alloc, SECOND_TABLE_SIZE * sizeof(taint_t *), 200);
    new_slab_alloc((char *)"3TABLE_ALLOC", &third_table_alloc, THIRD_TABLE_SIZE * sizeof(taint_t), 100000);
#ifdef TAINT_FULL_DEBUG
    leaf_node_addrs = g_hash_table_new(g_direct_hash, g_direct_equal);
    merge_node_addrs = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif
}

#ifdef TAINT_STRUCTS_WRITEOUT
int init_writeout_files(char* group_dir)
{
    char leaf_filename[256];
    char node_filename[256];

    snprint(leaf_filename, 256, "%s/leafs", group_dir);
    snprint(node_filename, 256, "%s/nodes", group_dir);

    leaf_fd = open(leaf_filename, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (leaf_fd < 0) {
        fprintf(stderr, "could not open leaf_fd, errno %d\n", errno);
        return -1;
    }

    node_fd = open(node_filename, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (node_fd < 0) {
        fprintf(stderr, "could not open node_fd, errno %d\n", errno);
        return -1;
    }
}
#endif

static inline struct taint_leafnode* get_new_leafnode(option_t option)
{
    struct taint_leafnode* ln;
    ln = (struct taint_leafnode *) get_slice(&leaf_alloc);
    assert(ln);
    memset(ln, 0, sizeof(struct taint_leafnode));
    ln->node.parent1 = NULL;
    ln->node.parent2 = NULL;
    ln->option = option;

#ifdef TAINT_STATS
    tsp.options++;
#endif
#ifdef TAINT_FULL_DEBUG
    g_hash_table_insert(leaf_node_addrs, (gpointer) ln, GINT_TO_POINTER(1));
#endif
    return ln;
}

static inline struct taint_node* get_new_taint_node(struct taint_node* parent1,
                                        struct taint_node* parent2)
{
    struct taint_node* n;
    n = (struct taint_node *) get_slice(&node_alloc);
    memset(n, 0, sizeof(struct taint_node));
    n->parent1 = parent1;
    n->parent2 = parent2;
#ifdef TAINT_FULL_DEBUG
    g_hash_table_insert(merge_node_addrs, (gpointer) n, GINT_TO_POINTER(1));
#endif
    return n;
}

static inline guint64* get_new_64()
{
    return (guint64 *) get_slice(&uint_alloc);
}

taint_t merge_taints(taint_t dst, taint_t src)
{
    if (dst == 0) {
        return src;
    }
    if (src == 0) {
        return dst;
    }
    if (dst == src) {
        return dst;
    }

#ifdef USE_MERGE_HASH
    taint_t h = src + dst;
    struct simple_bucket& bucket = simple_hash[h%SIMPLE_HASH_SIZE];
    if (bucket.p1 == src && bucket.p2 == dst) {
#ifdef TAINT_STATS
	tsp.merges_saved++;
#endif
	return bucket.n;
    } else {
	taint_t n = add_merge_number (dst, src);
	bucket.p1 = src;
	bucket.p2 = dst;
	bucket.n = n;
#ifdef TAINT_STATS
	tsp.merges++;
#endif
	return n;
    }
#else

#ifdef TAINT_STATS
    tsp.merges++;
#endif
    return add_merge_number(dst, src);
#endif
}

static inline unsigned get_high_index(u_long mem_loc)
{
    return (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS));
}

static inline unsigned get_mid_index(u_long mem_loc)
{
    return (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
}

static inline void* new_second_table(void)
{
    // TODO use a slab allocator
    void* second_table = get_slice(&second_table_alloc);
    memset(second_table, 0, SECOND_TABLE_SIZE * sizeof(taint_t*));
    assert(second_table);
#ifdef TAINT_STATS
    tsp.num_second_tables++;
#endif
    return second_table;
}

static inline void* new_third_table(u_long memloc)
{
    // TODO use a slab allocator
    taint_t* third_table = (taint_t *) get_slice(&third_table_alloc);
    if (splice_output) {
	memloc &= MIDHIGH_INDEX_MASK;
	for (int i = 0; i < THIRD_TABLE_SIZE; i++) {
	    third_table[i] = memloc++;
	}
    } else {
	memset(third_table, 0, THIRD_TABLE_SIZE * sizeof(taint_t));
    }
    assert(third_table);
#ifdef TAINT_STATS
    tsp.num_third_tables++;
#endif
    return third_table;
}

static inline int get_mem_split(u_long mem_loc, uint32_t size)
{
    if (get_high_index(mem_loc) == get_high_index(mem_loc + size - 1)) {
        if (get_mid_index(mem_loc) == get_mid_index(mem_loc + size - 1)) {
            return size;
        } else {
            unsigned bytes_left = (THIRD_TABLE_BITS + 1) - (mem_loc & 5);
            if ((size) > bytes_left) {
                assert(bytes_left != 0);
                return bytes_left;
            }
            return size;
        }
    } else {
        /*
        unsigned shiftpos;
        unsigned bytes_left;
        shiftpos = (1 << (SECOND_TABLE_BITS + THIRD_TABLE_BITS)); 
        bytes_left = shiftpos - (mem_loc & (shiftpos - 1));
        */
        unsigned bytes_left = HIGH_SHIFTPOS - (mem_loc & HIGH_SHIFTMASK);

        /*
        fprintf(stderr, "highindex: mem_loc is %lx, size is %d\n", mem_loc, size);
        fprintf(stderr, "highindex %u: mem_loc is %lx\n", get_high_index(mem_loc), mem_loc);
        fprintf(stderr, "highindex %u: mem_loc is %lx\n", get_high_index(mem_loc + size - 1), mem_loc + size - 1);
        fprintf(stderr, "bytes left is %u\n", bytes_left);
        assert(0);
        */
        if ((size) > bytes_left) {
            assert(bytes_left != 0);
            return bytes_left;
        }
        return size;
    }
}

taint_t create_and_taint_option (u_long mem_addr)
{
    taint_t t = taint_num++;
    taint_mem(mem_addr, t);
    return t;
}

taintvalue_t get_taint_value (taint_t t, option_t option)
{
    // STUB
    return 0;
}


void finish_and_print_taint_stats(FILE* fp)
{
    if (merge_buf_overflow) flush_merge_buffer ();

#ifdef TAINT_STATS
    fprintf(fp, "Taint statistics:\n");
    fprintf(fp, "Second tables allocated: %lu\n", tsp.num_second_tables);
    fprintf(fp, "Third tables allocated: %lu\n", tsp.num_third_tables);
    fprintf(fp, "Num taint options: %lu\n", tsp.options);
    fprintf(fp, "Num merges: %lu\n", tsp.merges);
    fprintf(fp, "Num merges saved: %lu\n", tsp.merges_saved);
    fflush(fp);
#endif
}

taint_t* get_reg_taints(int reg)
{
    return &(current_thread->shadow_reg_table[reg * REG_SIZE]);
}

void clear_reg (int reg, int size)
{
    int i = 0;
    taint_t* reg_table = current_thread->shadow_reg_table;

    for (i = 0; i < size; i++) {
        reg_table[reg * REG_SIZE + i] = 0;
    }
}

void taint_mem(u_long mem_loc, taint_t t)
{
    unsigned high_index;
    unsigned mid_index;
    unsigned low_index;
    taint_t** first_t;
    taint_t* second_t;

    high_index = (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS));
    if(!mem_loc_high[high_index]) {
        mem_loc_high[high_index] = new_second_table();
    }
    mid_index = (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
    first_t = (taint_t**) mem_loc_high[high_index];
    if(!first_t[mid_index]) {
        first_t[mid_index] = (taint_t *) new_third_table(mem_loc);
    }
    low_index = mem_loc & LOW_INDEX_MASK;
    second_t = first_t[mid_index];

    second_t[low_index] = t;
}

taint_t* get_mem_taints(u_long mem_loc, uint32_t size)
{
    unsigned location = (unsigned) mem_loc;
    unsigned high_index = get_high_index(mem_loc);
    taint_t** first = (taint_t **) mem_loc_high[high_index];
    if(!first) {
	if (splice_output) {
	    // Uninitialized - create table with correct values
	    mem_loc_high[high_index] = new_second_table();
	    first = (taint_t **) mem_loc_high[high_index];
	} else {
	    return NULL;
	}
    }

    unsigned mid_index = get_mid_index(mem_loc);
    taint_t* second = first[mid_index];
    if(!second) {
	if (splice_output) {
	    first[mid_index] = (taint_t *) new_third_table(mem_loc);
	    second = first[mid_index];
	} else {
	    return NULL;
	}
    }

    unsigned low_index = location & LOW_INDEX_MASK;
    return second + low_index;
}

#define DUMPBUFSIZE 1000000
static taint_t dumpbuf[DUMPBUFSIZE];
static u_long dumpindex = 0;

static void flush_dumpbuf(int dumpfd)
{
    long rc = write (dumpfd, dumpbuf, dumpindex*sizeof(taint_t));
    if (rc != (long) (dumpindex*sizeof(taint_t))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
    }
    dumpindex = 0;
}

static inline void print_value (int dumpfd, taint_t value) 
{
    if (dumpindex == DUMPBUFSIZE) flush_dumpbuf(dumpfd);
    dumpbuf[dumpindex++] = value;
}

int dump_mem_taints(int fd)
{
    u_long addr;
    int high_index, mid_index, low_index;

    for (high_index = 0; high_index < FIRST_TABLE_SIZE; high_index++) {
	taint_t** first = (taint_t **) mem_loc_high[high_index];
	if (first) {
	    for (mid_index = 0; mid_index < SECOND_TABLE_SIZE; mid_index++) {
		taint_t* second = first[mid_index];
		if (second) {
		    for (low_index = 0; low_index < THIRD_TABLE_SIZE; low_index++) {
			addr = (high_index<<(SECOND_TABLE_BITS+THIRD_TABLE_BITS)) + (mid_index<<THIRD_TABLE_BITS) + low_index;
			if (second[low_index] != addr) {
			    print_value (fd, addr);
			    print_value (fd, second[low_index]);
#ifdef DEBUGTRACE
			    if (is_in_trace_set(second[low_index])) {
				printf ("addr %lx has taint value %lx\n", addr, second[low_index]);
			    }
#endif
			}
		    }
		}
	    }
	}
    }
    flush_dumpbuf(fd);
    return 0;
}

int dump_mem_taints_start(int fd)
{
    u_long addr;
    int high_index, mid_index, low_index;

    for (high_index = 0; high_index < FIRST_TABLE_SIZE; high_index++) {
	taint_t** first = (taint_t **) mem_loc_high[high_index];
	if (first) {
	    for (mid_index = 0; mid_index < SECOND_TABLE_SIZE; mid_index++) {
		taint_t* second = first[mid_index];
		if (second) {
		    for (low_index = 0; low_index < THIRD_TABLE_SIZE; low_index++) {
			addr = (high_index<<(SECOND_TABLE_BITS+THIRD_TABLE_BITS)) + (mid_index<<THIRD_TABLE_BITS) + low_index;
			if (second[low_index]) {
			    print_value (fd, addr);
			    print_value (fd, second[low_index]);
#ifdef DEBUGTRACE
			    if (is_in_trace_set(second[low_index])) {
				printf ("addr %lx has taint value %lx\n", addr, second[low_index]);
			    }
#endif
			}
		    }
		}
	    }
	}
    }
    flush_dumpbuf(fd);
    return 0;
}

int dump_reg_taints (int fd, taint_t* pregs)
{
    u_long i;

    // Increment by 1 because 0 is reserved for "no taint"
    for (i = 0; i < NUM_REGS*REG_SIZE; i++) {
	if (pregs[i] != i+1) {
	    print_value (fd, i+1);
	    print_value (fd, pregs[i]);
#ifdef DEBUGTRACE
	    if (is_in_trace_set(pregs[i])) {
		printf ("reg %lx has taint value %lx\n", i, pregs[i]);
	    }
#endif
	}
    }

    return 0;
}

int dump_reg_taints_start (int fd, taint_t* pregs)
{
    u_long i;

    // Increment by 1 because 0 is reserved for "no taint"
    for (i = 0; i < NUM_REGS*REG_SIZE; i++) {
	if (pregs[i]) {
	    print_value (fd, i+1);
	    print_value (fd, pregs[i]);
#ifdef DEBUGTRACE
	    if (is_in_trace_set(pregs[i])) {
		printf ("reg %lx has taint value %lx\n", i, pregs[i]);
	    }
#endif
	}
    }

    return 0;
}

uint32_t get_cmem_taints(u_long mem_loc, uint32_t size, taint_t** mem_taints)
{
    unsigned high_index;
    unsigned bytes_left;
    unsigned location = (unsigned) mem_loc;

    bytes_left = get_mem_split(mem_loc, size);
    high_index = get_high_index(mem_loc);
    taint_t** first = (taint_t **) mem_loc_high[high_index];
    if(!first) {
	if (splice_output) {
	    // Uninitialized - create table with correct values
	    mem_loc_high[high_index] = new_second_table();
	    first = (taint_t **) mem_loc_high[high_index];
	} else {
	    *mem_taints = NULL;
	    return (size > bytes_left) ? bytes_left : size;
	}
    }

    unsigned mid_index = get_mid_index(mem_loc);
    taint_t* second = first[mid_index];
    if(!second) {
	if (splice_output) {
	    first[mid_index] = (taint_t *) new_third_table(mem_loc);
	    second = first[mid_index];
	} else {
	    *mem_taints = NULL;
	    return (size > bytes_left) ? bytes_left : size;
	}
    }

    unsigned low_index = location & LOW_INDEX_MASK;
    *mem_taints = second + low_index;
#ifdef TAINT_FULL_DEBUG
    check_mem_taints(*mem_taints, mem_loc, bytes_left);
#endif
    return bytes_left;
}

static void set_mem_taints(u_long mem_loc, uint32_t size, taint_t* values)
{
    unsigned high_index;
    unsigned mid_index;
    unsigned low_index;
    taint_t** first_t;
    taint_t* second_t;

    high_index = (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS));
    if(!mem_loc_high[high_index]) {
        mem_loc_high[high_index] = new_second_table();
    }
    mid_index = (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
    first_t = (taint_t**) mem_loc_high[high_index];
    if(!first_t[mid_index]) {
        first_t[mid_index] = (taint_t *) new_third_table(mem_loc);
    }
    low_index = mem_loc & LOW_INDEX_MASK;
    second_t = first_t[mid_index];

    memcpy((void *) (second_t + low_index), values, size * sizeof(taint_t));
#ifdef TAINT_FULL_DEBUG
    {
        int i = 0;
        taint_t* mem_taints;
        mem_taints = (taint_t *) (second_t + low_index);
        assert(values);
        for (i = 0; i < size; i++) {
            assert_valid_taint_addr(values[i]);
            assert_valid_taint_addr(mem_taints[i]);
        }
    }
#endif
}

/* Returns the number of bytes set in a memory location.
 *  This can be less than size if it requires walking over to another
 *   page table structure.
 *   This is a performance optimization.
 * */
uint32_t set_cmem_taints(u_long mem_loc, uint32_t size, taint_t* values)
{
    unsigned bytes_left;
    uint32_t set_size = 0;

    unsigned high_index;
    unsigned mid_index;
    unsigned low_index;
    taint_t** first_t;
    taint_t* second_t;

    bytes_left = get_mem_split(mem_loc, size);
    set_size = (size > bytes_left) ? bytes_left : size;

    high_index = (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS));
    if(!mem_loc_high[high_index]) {
        mem_loc_high[high_index] = new_second_table();
    }
    mid_index = (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
    first_t = (taint_t**) mem_loc_high[high_index];
    if(!first_t[mid_index]) {
        first_t[mid_index] = (taint_t *) new_third_table(mem_loc);
    }
    low_index = mem_loc & LOW_INDEX_MASK;
    second_t = first_t[mid_index];

    memcpy((void *) (second_t + low_index), values, set_size * sizeof(taint_t));
#ifdef TAINT_FULL_DEBUG
    {
        int i = 0;
        taint_t* mem_taints;
        assert(values);
        mem_taints = (taint_t *) (second_t + low_index);
        for (i = 0; i < set_size; i++) {
            assert_valid_taint_addr(values[i]);
            assert_valid_taint_addr(mem_taints[i]);
        }
    }
#endif

    return set_size;
}

/* Set a continuous range of memory to one taint value */
uint32_t set_cmem_taints_one(u_long mem_loc, uint32_t size, taint_t value)
{
    unsigned bytes_left;
    uint32_t set_size = 0;

    unsigned high_index;
    unsigned mid_index;
    unsigned low_index;
    taint_t** first_t;
    taint_t* second_t;

    bytes_left = get_mem_split(mem_loc, size);
    set_size = (size > bytes_left) ? bytes_left : size;

    high_index = (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS));
    if(!mem_loc_high[high_index]) {
        mem_loc_high[high_index] = new_second_table();
    }
    mid_index = (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
    first_t = (taint_t**) mem_loc_high[high_index];
    if(!first_t[mid_index]) {
        first_t[mid_index] = (taint_t *) new_third_table(mem_loc);
    }
    low_index = mem_loc & LOW_INDEX_MASK;
    second_t = first_t[mid_index];

    memset((void *) (second_t + low_index), value, set_size * sizeof(taint_t));
#ifdef TAINT_FULL_DEBUG
    {
        int i = 0;
        taint_t* mem_taints;
        assert_valid_taint_addr(value);

        mem_taints = (taint_t *) (second_t + low_index);

        for (i = 0; i < set_size; i++) {
            assert_valid_taint_addr(mem_taints[i]);
        }
    }
#endif
    return set_size;
}

uint32_t clear_cmem_taints(u_long mem_loc, uint32_t size)
{
    unsigned bytes_left;
    uint32_t set_size = 0;
    unsigned location = (unsigned) mem_loc;

    bytes_left = get_mem_split(mem_loc, size);
    set_size = (size > bytes_left) ? bytes_left : size;

    unsigned high_index = get_high_index(mem_loc);
    taint_t** first = (taint_t **) mem_loc_high[high_index];
    if(!first) {
	if (splice_output) {
	    // Uninitialized - create table with correct values
	    mem_loc_high[high_index] = new_second_table();
	    first = (taint_t **) mem_loc_high[high_index];
	} else {
	    return set_size;
	}
    }

    unsigned mid_index = get_mid_index(mem_loc);
    taint_t* second = first[mid_index];
    if(!second) {
	if (splice_output) {
	    first[mid_index] = (taint_t *) new_third_table(mem_loc);
	    second = first[mid_index];
	} else {
	    return set_size;
	}
    }

    unsigned low_index = location & LOW_INDEX_MASK;
    memset(second + low_index, 0, set_size * sizeof(taint_t));
#ifdef TAINT_FULL_DEBUG
    {
        int i = 0;
        taint_t* mem_taints;
        assert(values);
        mem_taints = (taint_t *) (second_t + low_index);
        for (i = 0; i < set_size; i++) {
            assert_valid_taint_addr(values[i]);
            assert_valid_taint_addr(mem_taints[i]);
        }
    }
#endif
    return set_size;
}

void clear_mem_taints(u_long mem_loc, uint32_t size)
{
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    while (offset < size) {
        uint32_t count = 0;
        count = clear_cmem_taints(mem_offset, size - offset);
        offset += count;
        mem_offset += count;
    }
}

static inline void clear_reg_value(int reg, int offset, int size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memset(&shadow_reg_table[reg * REG_SIZE + offset], 0,
            size * sizeof(taint_t));
#ifdef TAINT_FULL_DEBUG
    check_reg_taints(reg);
#endif
}

static inline void set_reg_value(int reg, int offset, int size, taint_t* values)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&shadow_reg_table[reg * REG_SIZE + offset], values,
            size * sizeof(taint_t));
#ifdef TAINT_FULL_DEBUG
    check_reg_taints(reg);
#endif
}

static inline void zero_partial_reg (int reg, int offset)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memset(&shadow_reg_table[reg * REG_SIZE + offset], 0,
            (REG_SIZE - offset) * sizeof(taint_t));
}

static inline void zero_partial_reg_until (int reg, int offset, int until)
{
    assert(until > offset);
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memset(&shadow_reg_table[reg * REG_SIZE + offset], 0,
            (until - offset) * sizeof(taint_t));
}

void init_taint_structures (char* group_dir)
{
    if (splice_output) {
	taint_num = 0xc0000001;
    } else {
	taint_num = 0x1;
    }
    memset(mem_loc_high, 0, FIRST_TABLE_SIZE * sizeof(void*));
    init_taint_index(group_dir);

    if (!taint_fds_table) {
        taint_fds_table = g_hash_table_new(g_direct_hash, g_direct_equal);
        taint_fds_cloexec = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
}

int translate_reg(int reg)
{
    if (reg == 25 || reg == 26 || reg == 27) {
        return 8;
    } else if (reg == 22 || reg == 23 || reg == 24) {
        return 9;
    } else if (reg == 28 || reg == 29 || reg == 30) {
        return 7;
    } else if (reg == 19 || reg == 20 || reg == 21) {
        return 10;
    }
    return reg;
}

void* get_non_zero_taints(taint_t t) {
    GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    GList* list = NULL;
    GQueue* queue = g_queue_new();
    struct taint_node* n = (struct taint_node *) t;

    g_queue_push_tail(queue, n);
    while(!g_queue_is_empty(queue)) {
        n = (struct taint_node *) g_queue_pop_head(queue);
        if (g_hash_table_lookup(seen_indices, n)) {
            continue;
        }
        g_hash_table_insert(seen_indices, n, GINT_TO_POINTER(1));

        if (!n->parent1 && !n->parent2) { // leaf node
            struct taint_leafnode* ln = (struct taint_leafnode *) n;
            list = g_list_prepend(list, GUINT_TO_POINTER(ln->option));
        } else {
            if (!g_hash_table_lookup(seen_indices, n->parent1)) {
                g_queue_push_tail(queue, n->parent1);
            }
            if (!g_hash_table_lookup(seen_indices, n->parent2)) {
                g_queue_push_tail(queue, n->parent2);
            }
        }
    }

    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
    return (void *) list;
}

void print_options(FILE* fp, taint_t t)
{
    GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    GList* list = NULL;
    GQueue* queue = g_queue_new();
    struct taint_node* n = (struct taint_node *) t;
    assert(n);

    g_queue_push_tail(queue, n);
    while(!g_queue_is_empty(queue)) {
        n = (struct taint_node *) g_queue_pop_head(queue);
        assert(n);
        if (g_hash_table_lookup(seen_indices, n)) {
            continue;
        }
        g_hash_table_insert(seen_indices, n, GINT_TO_POINTER(1));

        if (!n->parent1 && !n->parent2) { // leaf node
            struct taint_leafnode* ln = (struct taint_leafnode *) n;
            fprintf(fp, "%u, ", ln->option);
            list = g_list_prepend(list, GUINT_TO_POINTER(ln->option));
        } else {
            if (!g_hash_table_lookup(seen_indices, n->parent1)) {
                g_queue_push_tail(queue, n->parent1);
            }
            if (!g_hash_table_lookup(seen_indices, n->parent2)) {
                g_queue_push_tail(queue, n->parent2);
            }
        }
    }

    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
}

void shift_reg_taint_right(int reg, int shift)
{
    assert(shift > 0);
    if (shift > 15) {
        clear_reg(reg, REG_SIZE);
        return;
    } else {
        int i = 0;
        taint_t* reg_table = current_thread->shadow_reg_table;
        for (i = 0; i < (REG_SIZE - shift); i++) {
            reg_table[reg * REG_SIZE + i] = reg_table[reg * REG_SIZE + i + shift];
        }
        // zero shift amount
        for (i = (REG_SIZE - shift); i < REG_SIZE; i++) {
            reg_table[reg * REG_SIZE + i] = 0;
        }
    }
}

void reverse_reg_taint(int reg, int size)
{
    // Only support word-sized registers for now
    assert(size == 4);
    taint_t* reg_table = current_thread->shadow_reg_table;
    taint_t tmp;
    tmp = reg_table[reg * REG_SIZE];
    reg_table[reg * REG_SIZE] = reg_table[reg * REG_SIZE + 3];
    reg_table[reg * REG_SIZE + 3] = tmp;
    
    tmp = reg_table[reg * REG_SIZE + 1];
    reg_table[reg * REG_SIZE + 1] = reg_table[reg * REG_SIZE + 2];
    reg_table[reg * REG_SIZE + 2] = tmp;
}

// mem2reg
static inline void taint_mem2reg(u_long mem_loc, int reg, uint32_t size)
{
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = 0;
        count = get_cmem_taints(mem_offset, size - offset, &mem_taints);
        if (!mem_taints) {
	    zero_partial_reg_until(reg, offset, offset + count);
        } else {
            assert(mem_taints != NULL);
            set_reg_value(reg, offset, count, mem_taints);
        }
        offset += count;
        mem_offset += count;
    }
}

TAINTSIGN taint_mem2lbreg(u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2lbreg");
    taint_mem2reg(mem_loc, reg, 1);
}

TAINTSIGN taint_mem2ubreg(u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2ubreg");
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (!mem_taints) {
        clear_reg_value(reg, 1, 1);
        return;
    }
    set_reg_value(reg, 1, 1, mem_taints);
}

TAINTSIGN taint_mem2hwreg(u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2hwreg");
    taint_mem2reg(mem_loc, reg, 2);
}

TAINTSIGN taint_mem2wreg(u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2wreg");
    taint_mem2reg(mem_loc, reg, 4);
}

TAINTSIGN taint_mem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2dwreg");
    taint_mem2reg(mem_loc, reg, 8);
}

TAINTSIGN taint_mem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2qwreg");
    taint_mem2reg(mem_loc, reg, 16);
}

TAINTSIGN taint_bmem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_bmem2hwreg");
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_bmem2wreg");
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_bmem2dwreg");
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_bmem2qwreg");
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwmem2wreg");
    taint_mem2hwreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwmem2dwreg");
    taint_mem2hwreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwmem2qwreg");
    taint_mem2hwreg(mem_loc, reg);
}

TAINTSIGN taint_wmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_wmem2dwreg");
    taint_mem2wreg(mem_loc, reg);
}

TAINTSIGN taint_wmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_wmem2qwreg");
    taint_mem2wreg(mem_loc, reg);
}

TAINTSIGN taint_dwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_dwmem2qwreg");
    taint_mem2dwreg(mem_loc, reg);
}

// mem2reg extend
TAINTSIGN taintx_bmem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_bmem2hwreg");
    taint_mem2reg(mem_loc, reg, 1);
    zero_partial_reg(reg, 1);
}

TAINTSIGN taintx_bmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_bmem2wreg");
    taint_mem2reg(mem_loc, reg, 1);
    zero_partial_reg(reg, 1);
#if 0
    {
        taint_t* mem_taints;
        mem_taints = get_mem_taints(mem_loc, 1);
        if (mem_taints) {
            assert(get_reg_taints(reg)[0] == mem_taints[0]);
        }
    }
#endif
}

TAINTSIGN taintx_bmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_bmem2dwreg");
    taint_mem2reg(mem_loc, reg, 1);
    zero_partial_reg(reg, 1);
}

TAINTSIGN taintx_bmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_bmem2qwreg");
    taint_mem2reg(mem_loc, reg, 1);
    zero_partial_reg(reg, 1);
}


TAINTSIGN taintx_hwmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwmem2wreg");
    taint_mem2reg(mem_loc, reg, 2);
    zero_partial_reg(reg, 2);
}

TAINTSIGN taintx_hwmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwmem2dwreg");
    taint_mem2reg(mem_loc, reg, 2);
    zero_partial_reg(reg, 2);
}

TAINTSIGN taintx_hwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwmem2qwreg");
    taint_mem2reg(mem_loc, reg, 2);
    zero_partial_reg(reg, 2);
}

TAINTSIGN taintx_wmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_wmem2dwreg");
    taint_mem2reg(mem_loc, reg, 4);
    zero_partial_reg(reg, 4);
}

TAINTSIGN taintx_wmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_wmem2qwreg");
    taint_mem2reg(mem_loc, reg, 4);
    zero_partial_reg(reg, 4);
}

TAINTSIGN taintx_dwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_dwmem2qwreg");
    taint_mem2reg(mem_loc, reg, 8);
    zero_partial_reg(reg, 8);
}

// mem2reg add
static inline void taint_add_mem2reg (u_long mem_loc, int reg, uint32_t size)
{
    unsigned i = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = 0;
        count = get_cmem_taints(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
                // shadow_reg_table[reg * REG_SIZE + offset + i] =
                taint_t t =  merge_taints(shadow_reg_table[reg * REG_SIZE + offset + i],
                                                                    mem_taints[i]);
                set_reg_value(reg, offset + i, 1, &t);
            }
        } 
        offset += count;
        mem_offset += count;
    }
}

TAINTSIGN taint_add_bmem2lbreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_bmem2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        taint_t t = merge_taints(shadow_reg_table[reg * REG_SIZE], mem_taints[0]);
        set_reg_value(reg, 0, 1, &t);
    }
}

TAINTSIGN taint_add_bmem2ubreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_bmem2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        taint_t t = merge_taints(shadow_reg_table[reg * REG_SIZE + 1], mem_taints[0]);
        set_reg_value(reg, 1, 1, &t);
    }
}

TAINTSIGN taint_add_hwmem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_hwmem2hwreg");
    taint_add_mem2reg(mem_loc, reg, 2);
}

TAINTSIGN taint_add_wmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_wmem2wreg");
    taint_add_mem2reg(mem_loc, reg, 4);
}

TAINTSIGN taint_add_dwmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_dwmem2dwreg");
    taint_add_mem2reg(mem_loc, reg, 8);
}

TAINTSIGN taint_add_qwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_qwmem2qwreg");
    taint_add_mem2reg(mem_loc, reg, 16);
}

TAINTSIGN taint_add_bmem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_bmem2hwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        shadow_reg_table[reg * REG_SIZE] = merge_taints(shadow_reg_table[reg * REG_SIZE], mem_taints[0]);
    }
}

TAINTSIGN taint_add_bmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_bmem2wreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        shadow_reg_table[reg * REG_SIZE] = merge_taints(shadow_reg_table[reg * REG_SIZE], mem_taints[0]);
    }
}

TAINTSIGN taint_add_bmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_bmem2dwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        shadow_reg_table[reg * REG_SIZE] = merge_taints(shadow_reg_table[reg * REG_SIZE], mem_taints[0]);
    }
}

TAINTSIGN taint_add_bmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_bmem2qwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        shadow_reg_table[reg * REG_SIZE] = merge_taints(shadow_reg_table[reg * REG_SIZE], mem_taints[0]);
    }
}

TAINTSIGN taint_add_hwmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_hwmem2wreg");
    taint_add_mem2reg(mem_loc, reg, 2);
}

TAINTSIGN taint_add_hwmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_hwmem2dwreg");
    taint_add_mem2reg(mem_loc, reg, 2);
}

TAINTSIGN taint_add_hwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_hwmem2qwreg");
    taint_add_mem2reg(mem_loc, reg, 2);
}

TAINTSIGN taint_add_wmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_wmem2dwreg");
    taint_add_mem2reg(mem_loc, reg, 4);
}

TAINTSIGN taint_add_wmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_wmem2qwreg");
    taint_add_mem2reg(mem_loc, reg, 4);
}

TAINTSIGN taint_add_dwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_dwmem2qwreg");
    taint_add_mem2reg(mem_loc, reg, 8);
}

// mem2reg xchg
static inline int is_reg_zero(int reg, uint32_t size)
{
    unsigned i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    for (i = 0; i < size; i++) {
        if(shadow_reg_table[reg * REG_SIZE + i] != 0) {
            return 0;
        }
    }
    return 1;
}

TAINTSIGN taint_xchg_bmem2lbreg (u_long mem_loc, int reg)
{
    taint_t tmp;
    taint_t* mem_taints;
    TAINT_START("taint_xchg_bmem2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[reg * REG_SIZE];
    mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        shadow_reg_table[reg * REG_SIZE] = mem_taints[0];
    } else {
        shadow_reg_table[reg * REG_SIZE] = 0;
    }
    set_cmem_taints(mem_loc, 1, &tmp);
}

TAINTSIGN taint_xchg_bmem2ubreg (u_long mem_loc, int reg)
{
    taint_t tmp;
    taint_t* mem_taints;
    TAINT_START("taint_xchg_bmem2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[reg * REG_SIZE + 1];
    mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        shadow_reg_table[reg * REG_SIZE + 1] = mem_taints[0];
    } else {
        shadow_reg_table[reg * REG_SIZE + 1] = 0;
    }
    set_cmem_taints(mem_loc, 1, &tmp);
}

static inline void taint_xchg_mem2reg (u_long mem_loc, int reg, int size)
{
    int i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t tmp[size];
#ifdef TAINT_FULL_DEBUG
    assert(reg > 0 && reg <= 120);
    check_reg_taints(reg);
#endif

    // This can be optimized, we can optimize it need be
    for (i = 0; i < size; i++) {
        taint_t* mem_taints;
        mem_taints = get_mem_taints(mem_loc + i, 1);
        if (mem_taints) {
            tmp[i] = mem_taints[0];
        } else {
            tmp[i] = 0;
        }
    }

    // TODO remove this conditional
    if (is_reg_zero(reg, size)) {
        int offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = 0;
            count = clear_cmem_taints(mem_offset, size - offset);
            offset += count;
            mem_offset += count;
        }
    } else {
        int offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = 0;
            count = set_cmem_taints(mem_offset, size - offset,
                                    &shadow_reg_table[reg * REG_SIZE + offset]);
            offset += count;
            mem_offset += count;
        }
    }

    // now set the register taints
    memcpy(&shadow_reg_table[reg * REG_SIZE], &tmp, size * sizeof(taint_t));
}

TAINTSIGN taint_xchg_hwmem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_xchg_hwmem2hwreg");
    taint_xchg_mem2reg(mem_loc, reg, 2);
}

TAINTSIGN taint_xchg_wmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_xchg_hwmem2hwreg");
    taint_xchg_mem2reg(mem_loc, reg, 4);
}

TAINTSIGN taint_xchg_dwmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_xchg_hwmem2hwreg");
    taint_xchg_mem2reg(mem_loc, reg, 8);
}

TAINTSIGN taint_xchg_qwmem2qwreg( u_long mem_loc, int reg)
{
    TAINT_START("taint_xchg_hwmem2hwreg");
    taint_xchg_mem2reg(mem_loc, reg, 16);
}

// reg2mem
static inline void taint_reg2mem(u_long mem_loc, int reg, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
#ifdef TAINT_FULL_DEBUG
    assert(reg > 0 && reg <= 120);
    check_reg_taints(reg);
#endif
    // TODO remove this conditional
    if (is_reg_zero(reg, size)) {
        uint32_t offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = 0;
            count = clear_cmem_taints(mem_offset, size - offset);
            offset += count;
            mem_offset += count;
        }
    } else {
        uint32_t offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = 0;
            count = set_cmem_taints(mem_offset, size - offset,
                                    &shadow_reg_table[reg * REG_SIZE + offset]);
            offset += count;
            mem_offset += count;
        }
    }
}

TAINTSIGN taint_lbreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2mem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE]);
    }
}

TAINTSIGN taint_ubreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2mem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_hwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwreg2mem");
    taint_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_wreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_wreg2mem");
    taint_reg2mem(mem_loc, reg, 4);
}

TAINTSIGN taint_dwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_dwreg2mem");
    taint_reg2mem(mem_loc, reg, 8);
}

TAINTSIGN taint_qwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_qwreg2mem");
    taint_reg2mem(mem_loc, reg, 16);
}

TAINTSIGN taint_lbreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2hwmem");
    taint_reg2mem(mem_loc, reg, 1);
}

TAINTSIGN taint_lbreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2wmem");
    taint_reg2mem(mem_loc, reg, 1);
}

TAINTSIGN taint_lbreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2dwmem");
    taint_reg2mem(mem_loc, reg, 1);
}

TAINTSIGN taint_lbreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2qwmem");
    taint_reg2mem(mem_loc, reg, 1);
}

TAINTSIGN taint_ubreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2hwmem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_cmem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_ubreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2wmem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_ubreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2dwmem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_ubreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2qwmem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_hwreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwreg2wmem");
    taint_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_hwreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwreg2dwmem");
    taint_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_hwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwreg2qwmem");
    taint_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_wreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_wreg2dwmem");
    taint_reg2mem(mem_loc, reg, 4);
}

TAINTSIGN taint_wreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_wreg2qwmem");
    taint_reg2mem(mem_loc, reg, 4);
}

TAINTSIGN taint_dwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_dwreg2qwmem");
    taint_reg2mem(mem_loc, reg, 8);
}

// reg2mem extend
TAINTSIGN taintx_lbreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_lbreg2hwmem");
    taint_lbreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 1);
}

TAINTSIGN taintx_lbreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_lbreg2wmem");
    taint_lbreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 3);
}

TAINTSIGN taintx_lbreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_lbreg2dwmem");
    taint_lbreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 7);
}

TAINTSIGN taintx_lbreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_lbreg2qwmem");
    taint_lbreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 15);
}

TAINTSIGN taintx_ubreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_ubreg2hwmem");
    taint_ubreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 1);
}

TAINTSIGN taintx_ubreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_ubreg2wmem");
    taint_ubreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 3);
}

TAINTSIGN taintx_ubreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_ubreg2hwmem");
    taint_ubreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 7);
}

TAINTSIGN taintx_ubreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_ubreg2qwmem");
    taint_ubreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 15);
}


TAINTSIGN taintx_hwreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwreg2wmem");
    taint_hwreg2wmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 2, 2);
}

TAINTSIGN taintx_hwreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwreg2dwmem");
    taint_hwreg2wmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 2, 6);
}

TAINTSIGN taintx_hwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwreg2qwmem");
    taint_hwreg2wmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 2, 14);
}

TAINTSIGN taintx_wreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_wreg2dwmem");
    taint_wreg2dwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 4, 4);
}

TAINTSIGN taintx_wreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_wreg2qwmem");
    taint_wreg2dwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 4, 12);
}

TAINTSIGN taintx_dwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_dwreg2qwmem");
    taint_dwreg2qwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 8, 8);
}

// reg2mem add
static inline void taint_add_reg2mem (u_long mem_loc, int reg, uint32_t size)
{
    unsigned i = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = 0;
        count = get_cmem_taints(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
                mem_taints[i] = merge_taints(shadow_reg_table[reg * REG_SIZE + offset + i], mem_taints[i]);
            }
        } else {
            // mem not tainted, just a set
            if (shadow_reg_table[reg * REG_SIZE]) {
                set_mem_taints(mem_offset, count, &shadow_reg_table[reg * REG_SIZE + offset]);
            }
        }
        offset += count;
        mem_offset += count;
    }
}

TAINTSIGN taint_add_lbreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_lbreg2mem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        mem_taints[0] = merge_taints(shadow_reg_table[reg * REG_SIZE], mem_taints[0]);
    } else {
        if (shadow_reg_table[reg * REG_SIZE]) {
            set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE]);
        }
    }
}

TAINTSIGN taint_add_ubreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_ubreg2mem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        mem_taints[0] = merge_taints(shadow_reg_table[reg * REG_SIZE + 1], mem_taints[0]);
    } else {
        if (shadow_reg_table[reg * REG_SIZE]) {
            set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
        }
    }
}

TAINTSIGN taint_add_hwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_hwreg2mem");
    taint_add_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_add_wreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_wreg2mem");
    taint_add_reg2mem(mem_loc, reg, 4);
}

TAINTSIGN taint_add_dwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_dwreg2mem");
    taint_add_reg2mem(mem_loc, reg, 8);
}

TAINTSIGN taint_add_qwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_qwreg2mem");
    taint_add_reg2mem(mem_loc, reg, 16);
}

TAINTSIGN taint_add_lbreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_lbreg2hwmem");
    taint_add_lbreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_lbreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_lbreg2wmem");
    taint_add_lbreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_lbreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_lbreg2dwmem");
    taint_add_lbreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_lbreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_lbreg2qwmem");
    taint_add_lbreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_ubreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_ubreg2hwmem");
    taint_add_ubreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_ubreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_ubreg2wmem");
    taint_add_ubreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_ubreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_ubreg2dwmem");
    taint_add_ubreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_ubreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_ubreg2qwmem");
    taint_add_ubreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_hwreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_hwreg2wmem");
    taint_add_hwreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_hwreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_hwreg2dwmem");
    taint_add_hwreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_hwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_hwreg2qwmem");
    taint_add_hwreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_wreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_wreg2dwmem");
    taint_add_wreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_wreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_wreg2qwmem");
    taint_add_wreg2mem(mem_loc, reg);
}

TAINTSIGN taint_add_dwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_add_dwreg2qwmem");
    taint_add_dwreg2mem(mem_loc, reg);
}

// reg2mem rep
TAINTSIGN taint_rep_lbreg2mem (u_long mem_loc, int reg, int count)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = shadow_reg_table[reg * REG_SIZE];
    uint32_t size = count;
    if (t) {
        unsigned i = 0; 
        while (i < size) {
            // FIXME: size is wrong on each iter
            i += set_cmem_taints_one(mem_loc + i, size, t);
        }
    } else {
        clear_mem_taints(mem_loc, size);
    }
}

TAINTSIGN taint_rep_ubreg2mem (u_long mem_loc, int reg, int count)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = shadow_reg_table[reg * REG_SIZE + 1];
    uint32_t size = count;
    if (t) {
        unsigned i = 0; 
        while (i < size) {
            // FIXME: size is wrong on each iter
            i += set_cmem_taints_one(mem_loc + i, size, t);
        }
    } else {
        clear_mem_taints(mem_loc, size);
    }
}

TAINTSIGN taint_rep_hwreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_hwreg2mem(mem_loc + (i * 2), reg);
    }
}

TAINTSIGN taint_rep_wreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_wreg2mem(mem_loc + (i * 4), reg);
    }
}

TAINTSIGN taint_rep_dwreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_dwreg2mem(mem_loc + (i * 8), reg);
    }
}

TAINTSIGN taint_rep_qwreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_qwreg2mem(mem_loc + (i * 16), reg);
    }
}

// reg2reg
static inline void taint_reg2reg (int dst_reg, int src_reg, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], size * sizeof(taint_t));
#ifdef TAINT_FULL_DEBUG
    check_reg_taints(dst_reg);
    check_reg_taints(src_reg);
#endif
}

TAINTSIGN taint_lbreg2lbreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2lbreg");
    taint_reg2reg(dst_reg, src_reg, 1);
}

TAINTSIGN taint_ubreg2lbreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_lbreg2ubreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    // shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
    shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_ubreg2ubreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_wreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_wreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 4);
}

TAINTSIGN taint_hwreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_hwreg2hwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_dwreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_dwreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 8);
}

TAINTSIGN taint_qwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_qwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 16);
}

TAINTSIGN taint_lbreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2wreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_lbreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2hwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_lbreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2dwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_lbreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2qwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_ubreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2hwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_ubreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2wreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_ubreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2dwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_ubreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2qwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_hwreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_hwreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_hwreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_hwreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_hwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_hwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_wreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_wreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 4);
}

TAINTSIGN taint_wreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_wreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 4);
}

TAINTSIGN taint_dwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_qwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 8);
}

// reg2reg extend
TAINTSIGN taintx_lbreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_lbreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_lbreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_lbreg2hwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_lbreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_lbreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_lbreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_lbreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_ubreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_ubreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_ubreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_ubreg2hwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_ubreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_ubreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_ubreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_ubreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_hwreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_hwreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 2);
    zero_partial_reg(dst_reg, 2);
}

TAINTSIGN taintx_hwreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_hwreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
    zero_partial_reg(dst_reg, 2);
}

TAINTSIGN taintx_hwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_hwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
    zero_partial_reg(dst_reg, 2);
}

TAINTSIGN taintx_wreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_wreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 4);
    zero_partial_reg(dst_reg, 4);
}

TAINTSIGN taintx_wreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_wreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 4);
    zero_partial_reg(dst_reg, 4);
}

TAINTSIGN taintx_dwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_dwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 8);
    zero_partial_reg(dst_reg, 8);
}

// reg2reg add
static inline void taint_add_reg2reg (int dst_reg, int src_reg, uint32_t size)
{
    unsigned i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    for (i = 0; i < size; i++) {
        shadow_reg_table[dst_reg * REG_SIZE + i] = merge_taints(shadow_reg_table[dst_reg * REG_SIZE + i], shadow_reg_table[src_reg * REG_SIZE + i]);
    } 
}

TAINTSIGN taint_add_lbreg2lbreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_lbreg2lbreg");
    taint_add_reg2reg(dst_reg, src_reg, 1);
}

TAINTSIGN taint_add_ubreg2lbreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_ubreg2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = merge_taints(shadow_reg_table[dst_reg * REG_SIZE], shadow_reg_table[src_reg * REG_SIZE + 1]);
}

TAINTSIGN taint_add_lbreg2ubreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_lbreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE + 1] = merge_taints(shadow_reg_table[dst_reg * REG_SIZE + 1], shadow_reg_table[src_reg * REG_SIZE]);
}

TAINTSIGN taint_add_ubreg2ubreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_ubreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE + 1] = merge_taints(shadow_reg_table[dst_reg * REG_SIZE + 1], shadow_reg_table[src_reg * REG_SIZE + 1]);
}

TAINTSIGN taint_add_wreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_wreg2wreg");
    taint_add_reg2reg(dst_reg, src_reg, 4);
}

TAINTSIGN taint_add_hwreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_hwreg2hwreg");
    taint_add_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_add_dwreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_dwreg2dwreg");
    taint_add_reg2reg(dst_reg, src_reg, 8);
}

TAINTSIGN taint_add_qwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_qwreg2qwreg");
    taint_add_reg2reg(dst_reg, src_reg, 16);
}

TAINTSIGN taint_add_lbreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_lbreg2wreg");
    taint_add_lbreg2lbreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_lbreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_lbreg2hwreg");
    taint_add_lbreg2lbreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_lbreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_lbreg2dwreg");
    taint_add_lbreg2lbreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_lbreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_lbreg2qwreg");
    taint_add_lbreg2lbreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_ubreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_ubreg2hwreg");
    taint_add_ubreg2lbreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_ubreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_ubreg2wreg");
    taint_add_ubreg2lbreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_ubreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_ubreg2dwreg");
    taint_add_ubreg2lbreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_ubreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_ubreg2qwreg");
    taint_add_ubreg2lbreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_hwreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_hwreg2wreg");
    taint_add_hwreg2hwreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_hwreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_hwreg2dwreg");
    taint_add_hwreg2hwreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_hwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_hwreg2qwreg");
    taint_add_hwreg2hwreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_wreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_wreg2dwreg");
    taint_add_wreg2wreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_wreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_wreg2qwreg");
    taint_add_wreg2wreg(dst_reg, src_reg);
}

TAINTSIGN taint_add_dwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_add_dwreg2qwreg");
    taint_add_dwreg2qwreg(dst_reg, src_reg);
}

// reg2reg xchg
TAINTSIGN taint_xchg_lbreg2lbreg (int dst_reg, int src_reg)
{
    taint_t tmp;
    TAINT_START("taint_xchg_lbreg2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[dst_reg * REG_SIZE];
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
    shadow_reg_table[src_reg * REG_SIZE] = tmp;
}

TAINTSIGN taint_xchg_ubreg2ubreg (int dst_reg, int src_reg)
{
    taint_t tmp;
    TAINT_START("taint_xchg_ubreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[dst_reg * REG_SIZE + 1];
    shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE + 1];
    shadow_reg_table[src_reg * REG_SIZE + 1] = tmp;
}

TAINTSIGN taint_xchg_ubreg2lbreg (int dst_reg, int src_reg)
{
    taint_t tmp;
    TAINT_START("taint_xchg_ubreg2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[dst_reg * REG_SIZE + 1];
    shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE];
    shadow_reg_table[src_reg * REG_SIZE] = tmp;
}

TAINTSIGN taint_xchg_lbreg2ubreg (int dst_reg, int src_reg)
{
    taint_t tmp;
    TAINT_START("taint_xchg_lbreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[dst_reg * REG_SIZE];
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
    shadow_reg_table[src_reg * REG_SIZE + 1] = tmp;
}

TAINTSIGN taint_xchg_hwreg2hwreg (int dst_reg, int src_reg)
{
    taint_t tmp[2];
    TAINT_START("taint_xchg_hwreg2hwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&tmp, &shadow_reg_table[dst_reg * REG_SIZE], 2 * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], 2 * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg * REG_SIZE], &tmp, 2 * sizeof(taint_t));
}

TAINTSIGN taint_xchg_wreg2wreg (int dst_reg, int src_reg)
{
    taint_t tmp[4];
    TAINT_START("taint_xchg_wreg2wreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&tmp, &shadow_reg_table[dst_reg * REG_SIZE], 4 * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], 4 * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg * REG_SIZE], &tmp, 4 * sizeof(taint_t));
}

TAINTSIGN taint_xchg_dwreg2dwreg (int dst_reg, int src_reg)
{
    taint_t tmp[8];
    TAINT_START("taint_xchg_dwreg2dwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&tmp, &shadow_reg_table[dst_reg * REG_SIZE], 8 * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], 8 * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg * REG_SIZE], &tmp, 8 * sizeof(taint_t));
}

TAINTSIGN taint_xchg_qwreg2qwreg (int dst_reg, int src_reg)
{
    taint_t tmp[16];
    TAINT_START("taint_xchg_qwreg2qwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&tmp, &shadow_reg_table[dst_reg * REG_SIZE], 16 * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], 16 * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg * REG_SIZE], &tmp, 16 * sizeof(taint_t));
}

TAINTSIGN taint_mask_reg2reg (int dst_reg, int src_reg)
{
    taint_t merge_taint;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    merge_taint = merge_taints(shadow_reg_table[src_reg * REG_SIZE + 3],
                                    shadow_reg_table[src_reg * REG_SIZE + 7]);
    merge_taint = merge_taints(merge_taint, shadow_reg_table[src_reg * REG_SIZE + 11]);
    merge_taint = merge_taints(merge_taint, shadow_reg_table[src_reg * REG_SIZE + 15]);
    // this is overtainting, but we don't track taint at the bit-level
    shadow_reg_table[dst_reg * REG_SIZE] = merge_taint;
}

// mem2mem
TAINTSIGN taint_mem2mem (u_long src_loc, u_long dst_loc, uint32_t size)
{
    // TODO: This can be optimized, by minimizng the number of walks through the
    // page table structure
    unsigned i = 0;
    taint_t* dst_mem_taint;
    taint_t* src_mem_taint;
    for (i = 0; i < size; i++) {
        dst_mem_taint = get_mem_taints(dst_loc + i, 1);
        src_mem_taint = get_mem_taints(src_loc + i, 1);

        if (!src_mem_taint && !dst_mem_taint) {
            continue;
        } else if (!src_mem_taint) {
            clear_mem_taints(dst_loc + i, 1);
        } else {
            set_mem_taints(dst_loc + i, 1, src_mem_taint);
        }
    }
}

TAINTSIGN taint_mem2mem_b (u_long src_loc, u_long dst_loc)
{
    taint_t* dst_mem_taints = get_mem_taints(dst_loc, 1);
    taint_t* src_mem_taints = get_mem_taints(dst_loc, 1);
    if (!src_mem_taints && !dst_mem_taints) {
        return;
    } else if (!src_mem_taints) {
        clear_mem_taints(dst_loc, 1);
    } else {
        set_mem_taints(dst_loc, 1, src_mem_taints);
    }
}

TAINTSIGN taint_mem2mem_hw (u_long src_loc, u_long dst_loc)
{
    taint_mem2mem(src_loc, dst_loc, 2);
}

TAINTSIGN taint_mem2mem_w (u_long src_loc, u_long dst_loc)
{
    taint_mem2mem(src_loc, dst_loc, 4);
}

TAINTSIGN taint_mem2mem_dw (u_long src_loc, u_long dst_loc)
{
    taint_mem2mem(src_loc, dst_loc, 8);
}

TAINTSIGN taint_mem2mem_qw (u_long src_loc, u_long dst_loc)
{
    taint_mem2mem(src_loc, dst_loc, 16);
}

static inline void taint_add_mem2mem (u_long src_loc, u_long dst_loc, uint32_t size)
{
    // TODO: This can be optimized, by minimizng the number of walks through the
    // page table structure
    unsigned i = 0;
    taint_t* dst_mem_taint;
    taint_t* src_mem_taint;
    for (i = 0; i < size; i++) {
        dst_mem_taint = get_mem_taints(dst_loc + i, 1);
        src_mem_taint = get_mem_taints(src_loc + i, 1);

        if (!src_mem_taint) {
            continue;
        } else if (!dst_mem_taint) {
            set_mem_taints(dst_loc + i, 1, src_mem_taint);
        } else {
            taint_t merged_taint;
            merged_taint = merge_taints(dst_mem_taint[0], src_mem_taint[0]);
            set_mem_taints(dst_loc + i, 1, &merged_taint);
        }
    }
}

TAINTSIGN taint_add_mem2mem_b (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 1);
}

TAINTSIGN taint_add_mem2mem_hw (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 2);
}

TAINTSIGN taint_add_mem2mem_w (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 4);
}

TAINTSIGN taint_add_mem2mem_dw (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 8);
}

TAINTSIGN taint_add_mem2mem_qw (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 16);
}

// 3-way operations (for supporting instructions like mul and div)
TAINTSIGN taint_add2_bmemlbreg_hwreg (u_long mem_loc, int src_reg, int dst_reg)
{
    taint_t merged_taint;
    taint_t* mem_taints;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        merged_taint = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE]);
        shadow_reg_table[dst_reg * REG_SIZE] = merged_taint;
        shadow_reg_table[dst_reg * REG_SIZE + 1] = merged_taint;
    } else {
        shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
        shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE];
    }
}

TAINTSIGN taint_add2_hwmemhwreg_2hwreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[2];
    taint_t final_merged_taint;

    mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        merged_taints[0] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE]);
    } else {
        merged_taints[0] = shadow_reg_table[src_reg * REG_SIZE];
    }
    mem_taints = get_mem_taints(mem_loc + 1, 1);
    if (mem_taints) {
        merged_taints[1] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE + 1]);
    } else {
        merged_taints[1] = shadow_reg_table[src_reg * REG_SIZE + 1];
    }
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add2_wmemwreg_2wreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2)
{
    int i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[4];
    taint_t final_merged_taint;

    for (i = 0; i < 4; i++) {
        mem_taints = get_mem_taints(mem_loc + i, 1);
        if (mem_taints) {
            merged_taints[i] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE + i]);
        } else {
            merged_taints[i] = shadow_reg_table[src_reg * REG_SIZE + i];
        }
    }
    final_merged_taint = merged_taints[0];
    for (i = 1; i < 4; i++) {
        final_merged_taint = merge_taints(final_merged_taint, merged_taints[i]);
    }
    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 3] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 3] = final_merged_taint;
}

TAINTSIGN taint_add2_lbreglbreg_hwreg (int src_reg1, int src_reg2, int dst_reg)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t final_merged_taint;

    final_merged_taint = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                        shadow_reg_table[src_reg2 * REG_SIZE]);

    shadow_reg_table[dst_reg * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add2_hwreghwreg_2hwreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[2];
    taint_t final_merged_taint;

    merged_taints[0] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                    shadow_reg_table[src_reg2 * REG_SIZE]);
    merged_taints[1] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 1]);
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add2_wregwreg_2wreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[4];
    taint_t final_merged_taint;

    merged_taints[0] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                    shadow_reg_table[src_reg2 * REG_SIZE]);
    merged_taints[1] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 1]);
    merged_taints[2] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 2],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 2]);
    merged_taints[3] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 3],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 3]);
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);
    final_merged_taint = merge_taints(final_merged_taint, merged_taints[2]);
    final_merged_taint = merge_taints(final_merged_taint, merged_taints[3]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 3] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 3] = final_merged_taint;
}

TAINTSIGN taint_add2_hwmemhwreg_2breg (u_long mem_loc,
                                    int src_reg, int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[2];
    taint_t final_merged_taint;

    mem_taints = get_mem_taints(mem_loc, 1);
    if (mem_taints) {
        merged_taints[0] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE]);
    } else {
        merged_taints[0] = shadow_reg_table[src_reg * REG_SIZE];
    }
    mem_taints = get_mem_taints(mem_loc + 1, 1);
    if (mem_taints) {
        merged_taints[1] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE + 1]);
    } else {
        merged_taints[1] = shadow_reg_table[src_reg * REG_SIZE + 1];
    }
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
}

TAINTSIGN taint_add2_wmemwreg_2hwreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2)
{
    int i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[4];
    taint_t final_merged_taint;

    for (i = 0; i < 4; i++) {
        mem_taints = get_mem_taints(mem_loc + i, 1);
        if (mem_taints) {
            merged_taints[i] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE + i]);
        } else {
            merged_taints[i] = shadow_reg_table[src_reg * REG_SIZE + i];
        }
    }
    final_merged_taint = merged_taints[0];
    for (i = 1; i < 4; i++) {
        final_merged_taint = merge_taints(final_merged_taint, merged_taints[i]);
    }
    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add3_dwmem2wreg_2wreg (u_long mem_loc,
                                    int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    int i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[8];
    taint_t final_merged_taint;

    for (i = 0; i < 4; i++) {
        mem_taints = get_mem_taints(mem_loc + i, 1);
        if (mem_taints) {
            merged_taints[i] = merge_taints(mem_taints[0], shadow_reg_table[src_reg1 * REG_SIZE + i]);
        } else {
            merged_taints[i] = shadow_reg_table[src_reg1 * REG_SIZE + i];
        }
    }
    for (i = 0; i < 4; i++) {
        mem_taints = get_mem_taints(mem_loc + 4 + i, 1);
        if (mem_taints) {
            merged_taints[i + 4] = merge_taints(mem_taints[0], shadow_reg_table[src_reg2 * REG_SIZE + i]);
        } else {
            merged_taints[i + 4] = shadow_reg_table[src_reg2 * REG_SIZE + i];
        }
    }

    final_merged_taint = merged_taints[0];
    for (i = 1; i < 8; i++) {
        final_merged_taint = merge_taints(final_merged_taint, merged_taints[i]);
    }
    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 3] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 3] = final_merged_taint;

}

TAINTSIGN taint_add2_2hwreg_2breg (int src_reg1, int src_reg2,
                                int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[2];
    taint_t final_merged_taint;

    merged_taints[0] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                    shadow_reg_table[src_reg2 * REG_SIZE]);
    merged_taints[1] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 1]);
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
}

TAINTSIGN taint_add3_2hwreg_2hwreg (int src_reg1, int src_reg2, int src_reg3,
                                    int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[4];
    taint_t final_merged_taint;

    merged_taints[0] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                    shadow_reg_table[src_reg3 * REG_SIZE]);
    merged_taints[1] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg3 * REG_SIZE + 1]);
    merged_taints[2] = merge_taints(shadow_reg_table[src_reg2 * REG_SIZE],
                                    shadow_reg_table[src_reg3 * REG_SIZE + 2]);
    merged_taints[3] = merge_taints(shadow_reg_table[src_reg2 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg3 * REG_SIZE + 3]);

    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);
    final_merged_taint = merge_taints(final_merged_taint, merged_taints[2]);
    final_merged_taint = merge_taints(final_merged_taint, merged_taints[3]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add3_2wreg_2wreg (int src_reg1, int src_reg2, int src_reg3,
                                    int dst_reg1, int dst_reg2)
{
    int i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[8];
    taint_t final_merged_taint;

    for (i = 0; i < 4; i++) {
        merged_taints[i] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + i],
                                        shadow_reg_table[src_reg3 * REG_SIZE + i]);
    }
    for (i = 0; i < 4; i++) {
        merged_taints[i + 4] = merge_taints(shadow_reg_table[src_reg2 * REG_SIZE + i],
                                        shadow_reg_table[src_reg3 * REG_SIZE + 4 + i]);
    }

    final_merged_taint = merged_taints[0];
    for (i = 1; i < 8; i++) {
        final_merged_taint = merge_taints(final_merged_taint, merged_taints[i]);
    }
    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 3] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 3] = final_merged_taint;
}

// immval2mem
TAINTSIGN taint_immvalb2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 1);
}

TAINTSIGN taint_immvalhw2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 2);
}

TAINTSIGN taint_immvalw2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 4);
}

TAINTSIGN taint_immvaldw2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 8);
}

TAINTSIGN taint_immvalqw2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 16);
}

// immval2mem add
TAINTSIGN taint_add_immvalb2mem (u_long mem_loc)
{
    return;
}

TAINTSIGN taint_add_immvalhw2mem (u_long mem_loc)
{
    return;
}

TAINTSIGN taint_add_immvalw2mem (u_long mem_loc)
{
    return;
}

TAINTSIGN taint_add_immvaldw2mem (u_long mem_loc)
{
    return;
}

TAINTSIGN taint_add_immvalqw2mem (u_long mem_loc)
{
    return;
}

// immval2reg
TAINTSIGN taint_immval2lbreg(int reg)
{
}

TAINTSIGN taint_immval2ubreg(int reg)
{
    zero_partial_reg_until(reg, 0, 1);
}

TAINTSIGN taint_immval2hwreg(int reg)
{
    zero_partial_reg_until(reg, 0, 2);
}

TAINTSIGN taint_immval2wreg(int reg)
{
    zero_partial_reg_until(reg, 0, 4);
}

TAINTSIGN taint_immval2dwreg(int reg)
{
    zero_partial_reg_until(reg, 0, 8);
}

TAINTSIGN taint_immval2qwreg(int reg)
{
    zero_partial_reg_until(reg, 0, 16);
}

// immval2reg add
TAINTSIGN taint_add_immval2lbreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2ubreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2hwreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2wreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2dwreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2qwreg(int reg)
{
    return;
}

TAINTSIGN taint_palignr_mem2dwreg(int reg, u_long mem_loc, int imm)
{
    int i = 0;
    taint_t tmp[16];
    taint_t* reg1;

    reg1 = get_reg_taints(reg);
    // concat dst:src
    for (i = 0; i < 8; i++) {
        taint_t* mem_taints;
        mem_taints = get_mem_taints(mem_loc + i, 1);
        if (mem_taints) {
            tmp[i] = mem_taints[0];
        } else {
            tmp[i] = 0;
        }
    }
    memcpy(&tmp[8], reg1, sizeof(taint_t) * 8);

    assert(imm >= 0 && imm < 8);
    set_reg_value(reg, 0, 8, &tmp[imm]);
}

TAINTSIGN taint_palignr_mem2qwreg(int reg, u_long mem_loc, int imm)
{
    int i = 0;
    taint_t tmp[32];
    taint_t* reg1;

    reg1 = get_reg_taints(reg);
    // concat dst:src
    for (i = 0; i < 16; i++) {
        taint_t* mem_taints;
        mem_taints = get_mem_taints(mem_loc + i, 1);
        if (mem_taints) {
            tmp[i] = mem_taints[0];
        } else {
            tmp[i] = 0;
        }
    }
    memcpy(&tmp[16], reg1, sizeof(taint_t) * 16);

    assert(imm >= 0 && imm < 16);
    set_reg_value(reg, 0, 16, &tmp[imm]);
}

TAINTSIGN taint_palignr_dwreg2dwreg(int dst_reg, int src_reg, int imm)
{
    taint_t tmp[16];
    taint_t* reg1;
    taint_t* reg2;

    reg1 = get_reg_taints(dst_reg);
    reg2 = get_reg_taints(src_reg);

    // concat dst:src
    memcpy(&tmp, reg2, sizeof(taint_t) * 8);
    memcpy(&tmp[8], reg1, sizeof(taint_t) * 8);

    assert(imm >= 0 && imm <= 8);
    set_reg_value(dst_reg, 0, 8, &tmp[imm]);
}

TAINTSIGN taint_palignr_qwreg2qwreg(int dst_reg, int src_reg, int imm)
{
    taint_t tmp[32];
    taint_t* reg1;
    taint_t* reg2;

    reg1 = get_reg_taints(dst_reg);
    reg2 = get_reg_taints(src_reg);

    // concat
    memcpy(&tmp, reg2, sizeof(taint_t) * 16);
    memcpy(&tmp[16], reg1, sizeof(taint_t) * 16);

    assert(imm >= 0 && imm < 16);
    set_reg_value(dst_reg, 0, 16, &tmp[imm]);
}

int add_taint_fd(int fd, int cloexec)
{
    g_hash_table_insert(taint_fds_table, GINT_TO_POINTER(fd), GINT_TO_POINTER(0));
    if (cloexec) {
        g_hash_table_insert(taint_fds_cloexec, GINT_TO_POINTER(fd), GINT_TO_POINTER(1));
    }
    return 0;
}

static void set_fd_taint(int fd, taint_t taint)
{
    g_hash_table_insert(taint_fds_table, GINT_TO_POINTER(fd), GINT_TO_POINTER(taint));
}

taint_t create_and_taint_fdset(int nfds, fd_set* fds)
{
    taint_t t = taint_num++;
    for (int i = 0; i < nfds; i++) {
        if (FD_ISSET(i, fds)) {
            set_fd_taint(i, t);
        }
    }
    return t;
}

int remove_taint_fd(int fd)
{
    if (g_hash_table_contains(taint_fds_cloexec, GINT_TO_POINTER(fd))) {
        g_hash_table_remove(taint_fds_cloexec, GINT_TO_POINTER(fd));
    } 
    return g_hash_table_remove(taint_fds_table, GINT_TO_POINTER(fd));
}

int remove_cloexec_taint_fds(void)
{
    assert(0);
    return 0;
}

int is_fd_tainted(int fd)
{
    return GPOINTER_TO_INT(g_hash_table_lookup(taint_fds_table,
                                            GINT_TO_POINTER(fd)));
}

void taint_fd(int fd, taint_t taint)
{
    set_fd_taint(fd, taint);
}

static void merge_fd_taint(int fd, taint_t taint)
{
    taint_t old_taint;
    taint_t new_taint;
    old_taint = GPOINTER_TO_INT(g_hash_table_lookup(taint_fds_table, GINT_TO_POINTER(fd)));
    new_taint = merge_taints(old_taint, taint);

    g_hash_table_insert(taint_fds_table, GINT_TO_POINTER(fd), GINT_TO_POINTER(new_taint));
}

void taint_mem2fd(u_long mem_loc, int fd)
{
    taint_t* mem_taints = NULL;
    uint32_t count = 0;
    count = get_cmem_taints(mem_loc, 1, &mem_taints);
    assert(count == 1);
    if (!mem_taints) {
        set_fd_taint(fd, mem_taints[0]);
    } else {
        set_fd_taint(fd, 0);
    }
}

void taint_mem2fd_size(u_long mem_loc, uint32_t size, int fd)
{
    assert(0);
}

void taint_reg2fd(int reg, int fd)
{
    assert(0);
}

void taint_add_mem2fd(u_long mem_loc, int fd)
{
    taint_t* mem_taints = NULL;
    taint_t* mt = NULL;
    uint32_t count = 0;
    count = get_cmem_taints(mem_loc, 1, &mem_taints);
    mt = get_mem_taints(mem_loc, 1);
    assert(mt == mem_taints);
    assert(count == 1);
    if (!mem_taints) {
        fprintf(stderr, "add from mem loc %lx to fd %d\n", mem_loc, fd);
        merge_fd_taint(fd, mem_taints[0]);
    } else {
        fprintf(stderr, "add from mem loc %lx is zero to fd %d\n", mem_loc, fd);
    }
    // else it's zero, so do nothing

}

void taint_add_reg2fd(int reg, int fd)
{
    assert(0);
}

void taint_fd2mem(u_long mem_loc, uint32_t size, int fd)
{
    taint_t t;
    unsigned i = 0;
    t = GPOINTER_TO_INT(g_hash_table_lookup(taint_fds_table,
                                            GINT_TO_POINTER(fd)));

    uint32_t nsize = size;
    while (i < size) {
        uint32_t inc = 0;
        inc += set_cmem_taints_one(mem_loc + i, nsize, t);
        i += inc;
        nsize -= inc;
    }
}

void taint_add_fd2mem(u_long mem_loc, uint32_t size, int fd)
{
    taint_t t;
    t = GPOINTER_TO_INT(g_hash_table_lookup(taint_fds_table,
                                            GINT_TO_POINTER(fd)));
    unsigned i = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = 0;
        count = get_cmem_taints(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
                mem_taints[i] = merge_taints(t, mem_taints[i]);
            }
        } else {
            // mem not tainted, just a set
            if (t) {
                set_mem_taints(mem_offset, count, &t);
            }
        }
        offset += count;
        mem_offset += count;
    }
}
