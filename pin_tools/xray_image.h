#ifndef XRAY_IMAGE_H
#define XRAY_IMAGE_H

#include <stdio.h>
#include <stdlib.h>
#include "list.h"

#define NAME_LEN 256

// Abstraction for list of image infos
// this will let me change the backing data structure for optimizations if necessary
struct image_infos {
    struct list_head infos;
};

struct image_info {
    unsigned long addr_start;
    unsigned long addr_end;
    unsigned long offset;   // loaded image offset
    int image_id;
    char name[NAME_LEN];
    struct list_head list;
};

// Function signatures
struct image_infos* new_image_infos(void);
struct image_info* new_image_info(unsigned long addr_start,
                                    unsigned long addr_end,
                                    unsigned long offset,
                                    int image_id, const char* name);
int add_image_info( struct image_infos* iis,
                    unsigned long addr_start,
                    unsigned long addr_end,
                    unsigned long offset,
                    int image_id,
                    const char* name);
unsigned long get_image_offset(struct image_infos* iis, unsigned long inst_ptr);
int remove_image_info(struct image_infos* iis, int image_id);

struct image_infos* new_image_infos()
{
    struct image_infos* iis;
    iis = (struct image_infos*) malloc(sizeof(struct image_info));
    INIT_LIST_HEAD (&iis->infos);
    
    return iis;
}

struct image_info* new_image_info(unsigned long addr_start,
                                    unsigned long addr_end,
                                    unsigned long offset,
                                    int image_id,
                                    const char* name)
{
    struct image_info* ii;
    ii = (struct image_info*) malloc(sizeof(struct image_info));

    ii->addr_start = addr_start;
    ii->addr_end = addr_end;
    ii->offset = offset;
    ii->image_id = image_id;
    strncpy(ii->name, name, NAME_LEN);

    return ii;
}

int add_image_info(struct image_infos* iis,
                    unsigned long addr_start,
                    unsigned long addr_end,
                    unsigned long offset,
                    int image_id,
                    const char* name)
{
    struct image_info* ii;
    ii = new_image_info(addr_start, addr_end, offset, image_id, name);

    list_add_tail (&ii->list, &iis->infos);
    
    return 0;
}

unsigned long get_image_offset(struct image_infos* iis, unsigned long inst_ptr)
{
    struct image_info* ii;
    list_for_each_entry (ii, &iis->infos, list) {
        if (inst_ptr >= ii->addr_start && inst_ptr < ii->addr_end) {
            return ii->offset;
        }
    }
    return 0;
}

unsigned long get_static_address(struct image_infos* iis, unsigned long inst_ptr)
{
    struct image_info* ii;
    unsigned long offset = 0;

    list_for_each_entry (ii, &iis->infos, list) {
        if (inst_ptr >= ii->addr_start && inst_ptr < ii->addr_end) {
            offset = ii->offset;
        }
    }
    return inst_ptr - offset;
}

char* get_image_name(struct image_infos* iis, unsigned long inst_ptr)
{
    struct image_info* ii;
    list_for_each_entry (ii, &iis->infos, list) {
        if (inst_ptr >= ii->addr_start && inst_ptr < ii->addr_end) {
            return ii->name;
        }
    }
    return NULL;
}

// Returns 0 on success, -1 on failure
int remove_image_info(struct image_infos* iis, int image_id)
{
    struct image_info* ii;
    struct image_info* iin;
    list_for_each_entry_safe (ii, iin, &iis->infos, list) {
        if (ii->image_id == image_id) {
            list_del (&ii->list);
            free(ii);
            return 0;
        } 
    }
    return -1;
}

#endif // end include guard XRAY_IMAGE_H
