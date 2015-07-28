#include <stdlib.h>
#include <assert.h>
#include <regex.h>
#include "../list.h"
#include "taint_creation.h"
#include "taint_interface.h"
#include "../xray_token.h"

int taint_filter_inputs = 0;
int taint_filter_outputs = 0;
u_long taint_filter_outputs_syscall = 0;

int inited_filters = 0;

/* List of filenames to create new taints from.
 * This list is for the entire replay group */
unsigned int num_filter_input_files = 0;
struct list_head filter_input_files;
struct filter_input_file {
    char filename[256];
    struct list_head list;
};
/* List of syscall indices to create new taints from
 * this list is for the entire replay group */
unsigned int num_filter_input_syscalls = 0;
struct list_head filter_input_syscalls;
struct filter_input_syscall {
    int syscall;
    struct list_head list;
};
/* List of regexes to create new taints from */
unsigned int num_filter_input_regexes = 0;
struct list_head filter_input_regexes;
struct filter_regex {
    regex_t regx;
    struct list_head list;
};
/* List of byte ranges to create new taints from */
unsigned int num_filter_byte_ranges = 0;
struct list_head filter_byte_ranges;
struct filter_byterange {
    int pid;
    int syscall;
    int start_offset;   // inclusive
    int end_offset;     // non-inclusive
    struct list_head list;
};

unsigned int num_filter_part_filenames = 0;
struct list_head filter_input_partfiles;
// Use struct filter_input_files

void set_filter_inputs(int f)
{
    taint_filter_inputs = f;
}

int filter_input(void)
{
    return taint_filter_inputs;
}

void set_filter_outputs(int f, u_long syscall)
{
    taint_filter_outputs = f;
    taint_filter_outputs_syscall = syscall;
}

void init_filters()
{
    if (!inited_filters) {
        // init the list of filters
        INIT_LIST_HEAD(&filter_input_files);
        INIT_LIST_HEAD(&filter_input_syscalls);
        INIT_LIST_HEAD(&filter_input_regexes);
        INIT_LIST_HEAD(&filter_byte_ranges);
        INIT_LIST_HEAD(&filter_input_partfiles);
        inited_filters = 1;
    }
}

void add_input_filter(int type, void* filter)
{
    if (type == FILTER_FILENAME) {
        struct filter_input_file* fif;
        fif = (struct filter_input_file*) malloc(sizeof(struct filter_input_file));
        strncpy(fif->filename,
                (char *) filter,
                256);
        list_add_tail(&fif->list, &filter_input_files);
        fprintf(stderr, "Added file to input list: %s\n",
                fif->filename);
        num_filter_input_files++;
    } else if (type == FILTER_SYSCALL) {
        struct filter_input_syscall* fis;
        fis = (struct filter_input_syscall*) malloc(sizeof(struct filter_input_syscall));
        fis->syscall = atoi((char *) filter);
        list_add_tail(&fis->list, &filter_input_syscalls);
        num_filter_input_syscalls++;
    } else if (type == FILTER_REGEX) {
        int rc;
        struct filter_regex* fir;
        fir = (struct filter_regex*) malloc(sizeof(struct filter_regex));
        rc = regcomp(&fir->regx, (char *) filter, REG_EXTENDED);
        fprintf(stderr, "compile regex %s\n", (char *) filter);
        if (rc) {
            fprintf(stderr, "Could not compile regex %s\n", (char *) filter);
            exit(-1);
        }
        list_add_tail(&fir->list, &filter_input_regexes);
        num_filter_input_regexes++;
    } else if (type == FILTER_BYTERANGE) {
        int rc;
        struct filter_byterange* fbr;
        fbr = (struct filter_byterange *) malloc(sizeof(struct filter_byterange));
        rc = sscanf((char *) filter, "%d,%d,%d,%d",
                &fbr->pid,
                &fbr->syscall,
                &fbr->start_offset,
                &fbr->end_offset);
        if (rc != 4) {
            fprintf(stderr, "Could not interpret filter byte range %s, %d\n",
                    (char *) filter, rc);
            exit(-1);
        }
        fprintf(stderr, "Filtering pid %d syscall %d [%d, %d)\n",
                fbr->pid, fbr->syscall, fbr->start_offset, fbr->end_offset);
        list_add_tail(&fbr->list, &filter_byte_ranges);
        num_filter_byte_ranges++;
    } else if (type == FILTER_PARTFILENAME) {
        struct filter_input_file* fif;
        fif = (struct filter_input_file*) malloc(sizeof(struct filter_input_file));
        strncpy(fif->filename, (char *) filter, 256);
        list_add_tail(&fif->list, &filter_input_partfiles);
        fprintf(stderr, "Added partial filename to input list: %s\n",
                                                            fif->filename);
        num_filter_part_filenames++;
    } else {
        assert(0);
    }
}

int filter_filename(char* filename) {
    struct filter_input_file* fif;
    list_for_each_entry(fif, &filter_input_files, list) {
        if (!strcmp(fif->filename, filename)) {
            return 1;
        }
    }
    return 0;
}

int filter_partfilename(char* filename) {
    struct filter_input_file* fif;
    list_for_each_entry(fif, &filter_input_files, list) {
        if (strstr(fif->filename, filename)) {
            return 1;
        }
    }
    return 0;
}

int filter_syscall(int syscall) {
    struct filter_input_syscall* fis;
    list_for_each_entry(fis, &filter_input_syscalls, list) {
        if (fis->syscall == syscall) {
            return 1;
        }
    }
    return 0;
}

int filter_regex(char* buf, int len) {
    int rc;
    struct filter_regex* fr;
    char buf_copy[len + 1];
    if (len <= 0) {
        return 0;
    }
    memcpy(buf_copy, buf, len);
    buf_copy[len] = '\0';
    list_for_each_entry(fr, &filter_input_regexes, list) {
        rc = regexec(&fr->regx, buf_copy, 0, NULL, 0);
        if (rc == 0) {
            fprintf(stderr, "MATCHED!\n");
            fprintf(stderr, "%s", buf_copy);
            fprintf(stderr, "\n");
            return 1;
        }
    }
    return 0;
}

// Assumes syscalls are uniquely ordered in a replay group,
// so don't the pid
int filter_byte_range(int syscall, int byteoffset)
{
    struct filter_byterange* fbr;
    fprintf(stderr, "filter byte range %d %d\n", syscall, byteoffset);
    list_for_each_entry(fbr, &filter_byte_ranges, list) {
        if (fbr->syscall == syscall &&
                byteoffset >= fbr->start_offset &&
                byteoffset < fbr->end_offset)
        {
            return 1;
        }
    }
    return 0;
}

void create_taints_from_buffer(void* buf, int size, 
			       struct taint_creation_info* tci,
			       int outfd,
			       char* channel_name)
{
    int i = 0;
    u_long buf_addr = (u_long) buf;
    if (size <= 0) return;
    if (!buf) return;

    // filtering, should return if none of the parameters match
    if (filter_input()) {
        int pass = 0;
        if (num_filter_input_files &&
                filter_filename(channel_name)) {
           pass = 1; 
        }
        else if (num_filter_part_filenames &&
                filter_partfilename(channel_name)) {
            pass = 1;
        }
        else if (num_filter_input_syscalls &&
                filter_syscall(tci->syscall_cnt)) {
            pass = 1;
        } else if (num_filter_input_regexes && 
                filter_regex((char *) buf, size)) {
            pass = 1;
        } 

        if (!pass && num_filter_byte_ranges == 0) {
            return;
        }
    }

    for (i = 0; i < size; i++) {
        if (filter_input() && num_filter_byte_ranges > 0 &&
                !filter_byte_range(tci->syscall_cnt, tci->offset + i)) {
            continue;
        }
        taint_mem(buf_addr + i, 1);
    }
}

void write_output_header(int outfd, struct taint_creation_info* tci,
                            void* buf, int buf_size)
{
    int rc;
    u_long bufaddr;

    if (!tci) {
        return;
    }
    rc = write(outfd, tci, sizeof(struct taint_creation_info));
    if (rc != sizeof(struct taint_creation_info)) {
        fprintf(stderr, "taint_byte_creation: write_output_header expected to \
                write struct taint_creation_info \
                size %d, got %d\n",
                sizeof(struct taint_creation_info), rc);
        return;
    }

    bufaddr = (u_long) buf;
    rc = write(outfd, &bufaddr, sizeof(u_long));
    if (rc != sizeof(bufaddr)) {
        fprintf(stderr, "taint_byte_creation: write_output_header expected \
                to write u_long size %d, got %d\n",
                sizeof(u_long), rc);
        return;
    }

    rc = write(outfd, &buf_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "taint_byte_creation: write_output_header expected \
                to write int size %d, got %d\n",
                sizeof(int), rc);
        return;
    }
}

void write_output_taints (int outfd, void* buf, int size)
{
    uint8_t* taints;
    int new_size;
    int rc;
    u_long new_buf = (u_long) buf;

    // round down to neaest factor of 8
    new_size = (new_buf % 8);
    new_buf = new_buf - (new_buf % 8);
    // round up to nearest factor of 8
    new_size += size;
    if ((new_buf + new_size) % 8) {
        new_size += (8 - ((new_buf + new_size) % 8));
    }
    
    /*
    fprintf(stderr, "new size is %d\n", new_size);
    fprintf(stderr, "buf is %lx, new buf is %lx, size %d new size %d\n",
            (u_long) buf, new_buf, size, new_size);
    */
    assert(new_size % 8 == 0);

    taints = (uint8_t *) get_mem_taints((u_long) buf, new_size);
    assert(taints);
    rc = write(outfd, taints, (sizeof(uint8_t) * (new_size / 8)));
    if (rc != (sizeof(uint8_t) * (new_size / 8))) {
        fprintf(stderr, "Could not write a tainted buffer\n");
    }
}

void output_buffer_result (void* buf, int size,
                                struct taint_creation_info* tci,
                                int outfd)
{
    write_output_header(outfd, tci, buf, size); 
    write_output_taints(outfd, buf, size);
}

void output_xcoords (int outfd, int syscall_cnt, 
                        int dest_x, int dest_y, u_long mem_loc)
{
}

int serialize_filters(int outfd)
{
    // This function saves all of the taint filter state so that
    // after an exec, it is all restored
    int rc;
    unsigned int count = 0;
    struct filter_input_file* fif;
    struct filter_input_syscall* fis;
    struct filter_regex* fir;
    struct filter_byterange* fbr;

    rc = write(outfd, &taint_filter_inputs, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write the taint_filter_inputs flag, errno %d\n", errno);
        return -1;
    }
    rc = write(outfd, &num_filter_input_files, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write num_filter_input_files, errno %d\n",
                errno);
        return -1;
    }
    list_for_each_entry(fif, &filter_input_files, list) {
        rc = write(outfd, fif, sizeof(struct filter_input_file));
        if (rc != sizeof(struct filter_input_file)) {
            fprintf(stderr, "Could not write a filter_input_file node, errno %d\n", errno);
            return -1;
        }
        count += 1;
    }
    assert(count == num_filter_input_files);
    count = 0;

    rc = write(outfd, &num_filter_input_syscalls, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write num_filter_input_syscalls, errno %d\n", errno);
        return -1;
    }
    list_for_each_entry(fis, &filter_input_syscalls, list) {
        rc = write(outfd, fis, sizeof(struct filter_input_syscall));
        if (rc != sizeof(struct filter_input_syscall)) {
            fprintf(stderr, "Could not write a filter_input_syscall node, errno %d\n", errno);
            return -1;
        }
        count += 1;
    }
    assert(count == num_filter_input_syscalls);
    count = 0;

    rc = write(outfd, &num_filter_input_regexes, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write num_filter_input_regexes, errno %d\n", errno);
        return -1;
    }
    list_for_each_entry(fir, &filter_input_regexes, list) {
        rc = write(outfd, fir, sizeof(struct filter_regex));
        if (rc != sizeof(struct filter_regex)) {
            fprintf(stderr, "Could not write a filter_regex node, errno %d\n", errno);
            return -1;
        }
        count += 1;
    }
    assert(count == num_filter_input_regexes);
    count = 0;

    rc = write(outfd, &num_filter_byte_ranges, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write num_filter_byte_ranges, errno %d\n", errno);
        return -1;
    }
    list_for_each_entry(fbr, &filter_byte_ranges, list) {
        rc = write(outfd, fbr, sizeof(struct filter_byterange));
        if (rc != sizeof(struct filter_byterange)) {
            fprintf(stderr, "could not write a filter_byterange node, errno %d\n", errno);
            return -1;
        }
        count += 1;
    }
    assert(count == num_filter_byte_ranges);
    count = 0;

    return 0;
}

int deserialize_filters(int infd)
{
    int rc;
    init_filters();

    rc = read(infd, &taint_filter_inputs, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "could not read taint_filter_inputs flag, errno %d\n", errno);
        return -1;
    }

    rc = read(infd, &num_filter_input_files, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not read num_filter_input_files, errno %d\n", errno);
        return -1;
    }
    for (unsigned i = 0; i < num_filter_input_files; i++) {
        struct filter_input_file tmp;
        struct filter_input_file* fif;
        fif = (struct filter_input_file*) malloc(sizeof(struct filter_input_file));
        rc = read(infd, &tmp, sizeof(struct filter_input_file));
        if (rc != sizeof(struct filter_input_file)) {
            fprintf(stderr, "problem reading filter_input_file node, errno %d\n", errno);
            return -1;
        }
        strncpy(fif->filename, tmp.filename, 256);
        list_add_tail(&fif->list, &filter_input_files);
    }
    rc = read(infd, &num_filter_input_syscalls, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not read num_filter_input_syscalls, errno %d\n", errno);
        return -1;
    }
    for (unsigned i = 0; i < num_filter_input_syscalls; i++) {
        struct filter_input_syscall tmp;
        struct filter_input_syscall* fis;
        fis = (struct filter_input_syscall*) malloc(sizeof(struct filter_input_syscall));
        rc = read(infd, &tmp, sizeof(struct filter_input_syscall));
        if (rc != sizeof(struct filter_input_syscall)) {
            fprintf(stderr, "problem reading filter_input_syscall node, errno %d\n", errno);
            return -1;
        }
        fis->syscall = tmp.syscall;
        list_add_tail(&fis->list, &filter_input_syscalls);
    }
    rc = read(infd, &num_filter_input_regexes, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not read num_filter_input_regexes, errno %d\n", errno);
        return -1;
    }
    for (unsigned i = 0; i < num_filter_input_regexes; i++) {
        int rc;
        struct filter_regex tmp;
        struct filter_regex* fir;
        fir = (struct filter_regex*) malloc(sizeof(struct filter_regex));
        rc = read(infd, &tmp, sizeof(struct filter_regex));
        if (rc != sizeof(struct filter_regex)) {
            fprintf(stderr, "Could not read filter_regex node, errno %d\n", errno);
            return -1;
        }
        memcpy(&fir->regx, &tmp.regx, sizeof(regex_t));
        list_add_tail(&fir->list, &filter_input_regexes);
    }
    rc = read(infd, &num_filter_byte_ranges, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not read num_filter_byte_ranges, errno %d\n", errno);
        return -1;
    }
    for (unsigned i = 0; i < num_filter_byte_ranges; i++) {
        struct filter_byterange tmp;
        struct filter_byterange* fbr;
        fbr = (struct filter_byterange *) malloc(sizeof(struct filter_byterange));
        rc = read(infd, &tmp, sizeof(struct filter_byterange));
        if (rc != sizeof(struct filter_byterange)) {
            fprintf(stderr, "Could not read filter_byterange node, errno %d\n", errno);
            return -1;
        }
        fbr->pid = tmp.pid;
        fbr->syscall = tmp.syscall;
        fbr->start_offset = tmp.start_offset;
        fbr->end_offset = tmp.end_offset;
        fprintf(stderr, "Restored filter pid %d syscall %d [%d, %d)\n",
                fbr->pid, fbr->syscall, fbr->start_offset, fbr->end_offset);
        list_add_tail(&fbr->list, &filter_byte_ranges);
    }

    return 0;
}

void build_filters_from_file(const char* filter_filename) {
    FILE* filter_f = NULL;
    size_t read;
    size_t len = 0;
    char* line = NULL;

    if (!filter_filename) {
        fprintf(stderr, "filter_filename is null.\n");
        exit(-1);
    }

    if (!filter_f) {
        filter_f = fopen(filter_filename, "r");
        if(!filter_f) {
            fprintf(stderr, "Couldn't open filter_read_filename %s\n", filter_filename);
            exit(-1);
        }
    }

    char filter_type;
    char filter[256];
    //int pid, syscall, start_offset, end_offset;
    while ((read = getline(&line, &len, filter_f)) != -1) {
        //sscanf(line, "-%c %d,%d,%d,%d\n", &filter_type, &pid, &syscall, &start_offset, &end_offset);
        sscanf(line, "-%c %s\n", &filter_type, filter);

        switch (filter_type) {
            case 'b':
                add_input_filter(FILTER_BYTERANGE, (void*) filter);
                break;
            default:
                break;
        }
    }


    return;
}
