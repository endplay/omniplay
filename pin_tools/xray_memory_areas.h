#ifndef XRAY_MEMORY_AREAS_H
#define XRAY_MEMORY_AREAS_H

#include "list.h"
#include <stdlib.h>
#include <stdio.h>


// structure representing a memory area
struct memory_area {
    unsigned long begin;
    unsigned long end;
    struct list_head list;
};


// abstraction for list of memory areas
// this will let me change the backing data structure for optimizations if necessary
struct memory_areas {
    struct list_head mas;
};

// function signatures
struct memory_areas* new_memory_areas(void);
int is_valid_address(struct memory_areas*, unsigned long addr);
int is_safe_area(struct memory_areas*, unsigned long start_addr, int size);
int add_memory_area(struct memory_areas*, unsigned long begin, unsigned long end);
int remove_memory_area(struct memory_areas*, unsigned long mbegin, unsigned long mend);
void print_memory_areas (FILE* fp, struct memory_areas* memory_areas);

struct memory_areas* new_memory_areas() 
{
    struct memory_areas* mas;
    mas = (struct memory_areas*) malloc(sizeof(struct memory_areas));
    INIT_LIST_HEAD (&mas->mas);

    return mas;
}

// Given a list of memory areas, checks to see if addr is a valid memory address
int is_valid_address(struct memory_areas* mas, unsigned long addr)
{
    struct memory_area* ma;
    struct list_head* memory_areas;

    memory_areas = &mas->mas;

    list_for_each_entry (ma, memory_areas, list) {
        if (addr >= ma->begin && addr < ma->end) {
            return 1;
        }
    }
    return 0;
}

// Given a list of memory areas, checks to see if the memory area starting at
// start_addr with size size is "safe". Safe being that the memory area 
// resides fully within a previous memory area.
int is_safe_area(struct memory_areas* mas, unsigned long start_addr, int size)
{
    struct memory_area* ma;
    struct list_head* memory_areas;

    memory_areas = &mas->mas;

    list_for_each_entry (ma, memory_areas, list) {
        if (start_addr >= ma->begin && start_addr+size-1 <= ma->end) {
            return 1;
        }
    }
    return 0;
}

int add_memory_area(struct memory_areas* mas, unsigned long begin, unsigned long end)
{
    struct memory_area* ma;
    struct memory_area* ma_next;
    struct list_head* memory_areas;

    unsigned long mbegin = begin;
    unsigned long mend = end;

    memory_areas = &mas->mas;

    // first need to check to see if this memory area exists

    list_for_each_entry_safe (ma, ma_next, memory_areas, list) {

        // matches exactly or falls exactly within
        if (mbegin >= ma->begin && mend <= ma->end) {
            // done
            return 0;
        }

        if (mbegin < ma->begin && mend <= ma->begin) {
            struct memory_area* new_ma;
            new_ma = (struct memory_area*) malloc(sizeof(struct memory_area));
            new_ma->begin = mbegin;
            new_ma->end = mend;
            list_add(&new_ma->list, (ma->list.prev));
            return 0;
        }

        if (mbegin < ma->begin && mend >= ma->begin) {
            struct memory_area* new_ma;
            new_ma = (struct memory_area*) malloc(sizeof(struct memory_area));
            new_ma->begin = mbegin;
            new_ma->end = ma->begin;
            list_add(&new_ma->list, (ma->list.prev));
            
            mbegin = ma->begin;
        }

        if (mbegin >= ma->begin && mbegin < ma->end && mend > ma->end) {
            mbegin = ma->end;
        }
    }

    ma = (struct memory_area*) malloc(sizeof(struct memory_area));
    ma->begin = mbegin;
    ma->end = mend;

    list_add_tail (&ma->list, memory_areas);

    return 0;
}

int remove_memory_area(struct memory_areas* mas, unsigned long mbegin, unsigned long mend)
{
    struct memory_area* ma;
    struct memory_area* ma_next;

    struct list_head* memory_areas;
    memory_areas = &mas->mas;

    // temporary variables
    unsigned long begin = mbegin;
    unsigned long end = mend;
    int done = 0;

    if (list_empty(memory_areas)) {
        return -1;
    }

    while (!done) {
        list_for_each_entry_safe (ma, ma_next, memory_areas, list) {
            // 4 cases:
            // 1) Memory area to remove matches memory area exactly
            if (ma->begin == begin && ma->end == end) {
                list_del (&ma->list);
                free(ma);
                return 0;
            }
            // 2) Memory area matches at the beginning
            if (ma->begin == begin && end < ma->end) {
                ma->begin = end;
                return 0;
            }
            // 3) Memory area matches at end
            if (ma->begin < begin && end == ma->end) {
                ma->end = begin;
                return 0;
            }
            // 4) Memory area matches in the middle
            if (ma->begin < begin && end < ma->end) {
                // new memory area
                struct memory_area* new_ma;
                new_ma = (struct memory_area*) malloc(sizeof(struct memory_area));
                new_ma->begin = end;
                new_ma->end = ma->end;
                list_add (&new_ma->list, &ma->list);

                //modify  the existing memory area
                ma->end = begin;
                return 0;
            }
            // 5) Memory area spans across existing memory areas
            if (ma->begin == begin && ma->end < end) {
                list_del (&ma->list);
                free(ma);

                // update the memory area to remove
                begin = ma->end;
            } else if (ma->begin < begin && begin < ma->end && ma->end < end) {
                unsigned long tmp;
                tmp = ma->end;
                ma->end = begin;

                // update the memory area to remove
                begin = tmp;
            } 
        }
    }
    // memory area not found
    return -1;
}

void print_memory_areas (FILE* fp, struct memory_areas* memory_areas)
{
    struct memory_area* ma;
    struct list_head* mas;

    mas = &memory_areas->mas;

    list_for_each_entry (ma, mas, list) {
        fprintf(fp, "[0x%lx, 0x%lx) ", ma->begin, ma->end);
        //fprintf(fp, "[0x%lu, 0x%lu) ", ma->begin, ma->end);
    }
    fprintf(fp, "\n");
}

#endif // end include guard XRAY_MEMORY_AREAS_H
