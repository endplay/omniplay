#include "xray_slab_alloc.h"
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

int inited = 0;
struct slab* slab_structs = NULL;
struct slab* slab_structs_end = NULL;

#define NUM_SLAB_STRUCTS 2097152

//#define ALLOC_STATS
#ifdef ALLOC_STATS
static u_long slab_allocated = 0;
#endif

void init_slab_allocs(void)
{
    unsigned long len;
    if (inited) {
        return;
    }
    len = sizeof(struct slab) * NUM_SLAB_STRUCTS;
    slab_structs = (struct slab *) mmap(NULL, len, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slab_structs == MAP_FAILED) {
        fprintf(stderr, "Could not allocate slab structs, errno %d\n", errno);
        assert(0);
    }
    assert((u_long)slab_structs != -1);
#ifdef ALLOC_STATS
    slab_allocated += len;
#endif
    slab_structs_end = slab_structs + NUM_SLAB_STRUCTS;
    inited = 1;
}

static struct slab* new_slab_struct(void) {
    struct slab* slab;
    slab = slab_structs;
    slab_structs++;
    if (slab_structs == slab_structs_end) {
        unsigned long len;
        len = sizeof(struct slab) * NUM_SLAB_STRUCTS;
        slab_structs = (struct slab *) mmap(NULL, len, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (slab_structs == MAP_FAILED) {
	    fprintf(stderr, "Could not allocate slab structs, errno %d\n", errno);
	    assert(0);
	}
#ifdef ALLOC_STATS
	slab_allocated += len;
#endif
        slab_structs_end = slab_structs + NUM_SLAB_STRUCTS;
        // XXX TODO We lose the reference here, if we want to garbage collect, we'll have to
        // clean this up later.
    }
    return slab;
}

static struct slab* new_slab(char* name, int size)
{
    struct slab* slab = new_slab_struct();
    assert(slab);
    slab->start = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slab->start == MAP_FAILED) {
        fprintf(stderr, "[%s] ERROR could not allocate new slab of size %d, errno %d\n",
		name, size, errno);
        assert(0);
    }
#ifdef ALLOC_STATS
    slab_allocated += size;
#endif

    slab->end = (void *) (((u_long) slab->start) + size);
#ifdef ALLOC_STATS
    fprintf(stderr, "[%s] creating new slab of size %d\n", name, size);
    fprintf(stderr, "[%s] total allocated %lu\n", name, slab_allocated);
#endif    
    return slab;
}

void new_slab_alloc(char* alloc_name, struct slab_alloc* alloc,
                        int slice_size, int num_slices)
{
    assert(alloc);
    strncpy(alloc->alloc_name, alloc_name, 256);
    alloc->slab_size = slice_size * num_slices;

    //fprintf(stderr, "[%s] Creating new slab allocate with slab size %d\n", alloc->alloc_name, alloc->slab_size);

    alloc->slice_size = slice_size;
    INIT_LIST_HEAD(&alloc->list);
    alloc->current_slab = new_slab(alloc_name, alloc->slab_size);
    list_add(&alloc->current_slab->list, &alloc->list);
    alloc->pos = alloc->current_slab->start;
    alloc->num_slabs = 1;
}

void* get_slice(struct slab_alloc* alloc)
{
    void* pos = alloc->pos;
    alloc->pos = (void *) (((u_long) alloc->pos) + alloc->slice_size);
    alloc->num_slices += 1;
    if (alloc->pos == alloc->current_slab->end) {
        alloc->current_slab = new_slab(alloc->alloc_name, alloc->slab_size);
        alloc->pos = alloc->current_slab->start;
        alloc->num_slabs++;
        list_add(&alloc->current_slab->list, &alloc->list);
    } 
    return pos;
}

void free_slices(struct slab_alloc* alloc)
{
    struct slab* s;
    struct slab* t;
    list_for_each_entry_safe (s, t, &(alloc->list), list) {
	assert (munmap (s->start, alloc->slab_size) == 0);
    }
    alloc->current_slab = new_slab(alloc->alloc_name, alloc->slab_size);
    list_add(&alloc->current_slab->list, &alloc->list);
    alloc->pos = alloc->current_slab->start;
    alloc->num_slabs = 1;
}

int serialize_slab_alloc(int outfd, struct slab_alloc* alloc)
{
    int rc = 0;
    struct slab* s;
    int count = 0;

    assert(alloc);

    // write the structure first
    rc = write(outfd, alloc, sizeof(struct slab_alloc));
    if (rc != sizeof(struct slab_alloc)) {
        fprintf(stderr, "serialize slab alloc: expected %d, got %d, errno %d\n",
                sizeof(struct slab_alloc), rc, errno);
        return rc;
    }
    count += rc;

    list_for_each_entry (s, &(alloc->list), list) {
        // write out the slab header
        rc = write(outfd, s, sizeof(struct slab));
        if (rc != sizeof(struct slab)) {
            fprintf(stderr, "serialize slab alloc: writing slab header expected %d, got %d, errno %d\n", sizeof(struct slab), rc, errno);
            return rc;
        }
        count += rc;

        // write out the contents of each of the slabs
        rc = write(outfd, s->start, alloc->slab_size);
        if (rc != alloc->slab_size) {
            fprintf(stderr, "serialize slab alloc: writing slab expected %d, got %d, errno %d\n", alloc->slab_size, rc, errno);
            return rc;
        }
        count += rc;
    }

    return count;
}
