#include <stdlib.h>
#include <assert.h>
#include <regex.h>
#include <sys/mman.h>
#include "../list.h"
#include "taint_creation.h"
#include "taint_interface.h"
#include "../xray_token.h"
#include "../taint_nw.h"

#ifdef TAINT_DEBUG
extern FILE* debug_f;
extern u_long* ppthread_log_clock;
extern u_long taint_debug_inst;
extern FILE* debug_f;
u_long debug_taint_cnt = 0;
#endif

extern taint_t taint_num;

int taint_filter_inputs = 0;
int taint_filter_outputs = 0;
u_long taint_filter_outputs_syscall = 0;

int inited_filters = 0;

u_long total_output_written = 0;

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
	if (fif == NULL) {
		fprintf (stderr, "Unable to malloc filter input file\n");
		assert (0);
	}
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
	if (fis == NULL) {
		fprintf (stderr, "Unable to malloc filter input syscall\n");
		assert (0);
	}
        fis->syscall = atoi((char *) filter);
        list_add_tail(&fis->list, &filter_input_syscalls);
        num_filter_input_syscalls++;
    } else if (type == FILTER_REGEX) {
        int rc;
        struct filter_regex* fir;
        fir = (struct filter_regex*) malloc(sizeof(struct filter_regex));
	if (fir == NULL) {
		fprintf (stderr, "Unable to malloc filter regex\n");
		assert (0);
	}
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
	if (fbr == NULL) {
		fprintf (stderr, "Unable to malloc filter byterange\n");
		assert (0);
	}
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
        //fprintf(stderr, "Filtering pid %d syscall %d [%d, %d)\n",
                //fbr->pid, fbr->syscall, fbr->start_offset, fbr->end_offset);
        list_add_tail(&fbr->list, &filter_byte_ranges);
        num_filter_byte_ranges++;
    } else if (type == FILTER_PARTFILENAME) {
        struct filter_input_file* fif;
        fif = (struct filter_input_file*) malloc(sizeof(struct filter_input_file));
	if (fif == NULL) {
		fprintf (stderr, "Unable to malloc filter input file\n");
		assert (0);
	}
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
    list_for_each_entry(fif, &filter_input_partfiles, list) {
        if (strstr(filename, fif->filename)) {
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

#if defined(USE_SHMEM) || defined(USE_NW)
#define TOKENBUFSIZE 0x2000
static struct token* tokenbuf;
static u_long tokenindex = 0;
#endif
#ifdef USE_SHMEM
static u_long token_total_count = 0;
#endif

#ifdef USE_NW
void flush_tokenbuf(int s)
{
    struct taint_data_header hdr;
    long bytes_written = 0;
    long size = tokenindex*sizeof(struct token);

    if(s == -99999) { 
	fprintf(stderr, "flush_tokenbuf, shouldn't write output\n");
	return;
    }

    hdr.type = TAINT_DATA_INPUT;
    hdr.datasize = size;
    long rc = write (s, &hdr, sizeof(hdr));
    if (rc != sizeof(hdr)) {
	fprintf (stderr, "Cannot write nw header for input data, rc=%ld, errno=%d\n", rc, errno);
	assert (0);
    }
    while (bytes_written < size) {
	rc = write (s, ((char *) tokenbuf)+bytes_written, size-bytes_written);	
	if (rc <= 0) {
	    fprintf (stderr, "Canot write to addr log, rc=%ld, errno=%d\n", rc, errno);
	    assert (0);
	}
	bytes_written += rc;
    }
    tokenindex = 0;
}

static void write_token_to_nw (int s, struct token* ptoken)
{
    if (tokenbuf == NULL) {
	tokenbuf = (struct token *) malloc (TOKENBUFSIZE*sizeof(struct token));
	if (tokenbuf == NULL) {
	    fprintf (stderr, "could not malloc token buffer, errno=%d\n", errno);
	    assert (0);
	}
    }
    if (tokenindex == TOKENBUFSIZE) flush_tokenbuf(s);
    tokenbuf[tokenindex++] = *ptoken;
}

void write_token_finish (int s) 
{
    flush_tokenbuf (s);
}

#endif
#ifdef USE_SHMEM
static void flush_tokenbuf(int tokenfd)
{
    			       
    token_total_count += tokenindex;//*sizeof(taint_t);woah, I think this was my bug? 

#ifdef TAINT_DEBUG
    fprintf (debug_f,"updated token_total_count to %lu\n", token_total_count);
#endif


    // Check for overflow
    if (token_total_count >= MAX_TOKENS_SIZE/sizeof(struct token)) {
	fprintf (stderr, "Cannot allocate any more token buffer than %ld\n", (u_long) token_total_count);
	assert (0);
    }

    // Unmap the current region
    if (munmap (tokenbuf, TOKENBUFSIZE*sizeof(struct token)) < 0) {
	fprintf (stderr, "could not munmap token buffer, errno=%d\n", errno);
	assert (0);
    }

    // Map in the next region
    tokenbuf = (struct token *) mmap (0, TOKENBUFSIZE*sizeof(struct token), PROT_READ|PROT_WRITE, MAP_SHARED, 
				      tokenfd, token_total_count*sizeof(struct token));
    if (tokenbuf == MAP_FAILED) {
	fprintf (stderr, "could not map token buffer, errno=%d\n", errno);
	assert (0);
    }
    tokenindex = 0;
}

static void write_token_to_shmem (int tokenfd, struct token* ptoken)
{
#ifdef TAINT_DEBUG
    fprintf (debug_f,"write_token_to_shm, index %lu, record_pid %d, syscall_cnt %d\n", token_total_count + tokenindex, ptoken->record_pid, ptoken->syscall_cnt);

#endif    

    if (tokenbuf == NULL) {
	tokenbuf = (struct token *) mmap (0, TOKENBUFSIZE*sizeof(struct token), PROT_READ|PROT_WRITE, MAP_SHARED, tokenfd, 0);
	if (tokenbuf == MAP_FAILED) {
	    fprintf (stderr, "could not map token buffer, errno=%d\n", errno);
	    assert (0);
	}
    }

    if (tokenindex == TOKENBUFSIZE) flush_tokenbuf(tokenfd);
    tokenbuf[tokenindex++] = *ptoken;
}

void write_token_finish (int tokenfd) 
{

#ifdef TAINT_DEBUG
    fprintf (debug_f, "write_token_finish: token_total_count %lu, curr_offset %lu, total bytes %lu \n", token_total_count, tokenindex, (token_total_count + tokenindex)*sizeof(struct token));
#endif

    int rc = ftruncate (tokenfd, (token_total_count+tokenindex)*sizeof(struct token));
    if (rc < 0) {
	fprintf (stderr, "Unable to truncate token shmem, rc=%d, errno=%d\n", rc, errno);
    }
    close (tokenfd);
}
#endif

void write_tokens_info(int outfd, taint_t start,
		       struct taint_creation_info* tci,
		       u_long size)
{
    struct token tok;
    set_new_token (&tok, tci->type, start, size, tci->syscall_cnt,
		   tci->offset, tci->rg_id, tci->record_pid, tci->fileno);

#ifdef USE_NW
    write_token_to_nw(outfd, &tok);
#endif
#ifdef USE_SHMEM
    write_token_to_shmem(outfd, &tok);
#endif
#ifdef USE_FILE
    write_token_to_file(outfd, &tok);
#endif
}

void create_taints_from_buffer(void* buf, int size, 
			       struct taint_creation_info* tci,
			       int outfd,
			       char* channel_name)
{

    int i = 0;
    taint_t start;
    u_long buf_addr = (u_long) buf;
    if (size <= 0) return;
    if (!buf) return;

    if(outfd == -99999) { 
	return;
    }

    // fprintf(stderr, "channel: %s, filter: %d\n", channel_name, filter_filename(channel_name));
    // fprintf(stderr, "hash: %u, filter: %d\n", hash, filter_call_stack(hash));
    // filtering, should return if none of the parameters match
    if (filter_input()) {
        int pass = 0;
        if (num_filter_input_files &&
                filter_filename(channel_name)) {
           pass = 1; 
        }
        if (num_filter_part_filenames &&
                filter_partfilename(channel_name)) {
            pass = 1;
        }
        if (num_filter_input_syscalls &&
                filter_syscall(tci->syscall_cnt)) {
            pass = 1;
        }
        if (num_filter_input_regexes && 
                filter_regex((char *) buf, size)) {
            pass = 1;
        } 

        if (!pass && num_filter_byte_ranges == 0) {
            return;
        }
    }

    start = taint_num;
    for (i = 0; i < size; i++) {
        if (filter_input() && num_filter_byte_ranges > 0 &&
                !filter_byte_range(tci->syscall_cnt, tci->offset + i)) {
	    if (taint_num != start) {
		write_tokens_info(outfd, start, tci, taint_num-start);
		start = taint_num;
	    }
            continue;
        }

        create_and_taint_option(buf_addr + i);
    }
    write_tokens_info(outfd, start, tci, size);
}

void create_fd_taints(int nfds, fd_set* fds, struct taint_creation_info* tci,
        int outfd)
{
    //void out the untracked process
    if (outfd == -99999) { 
	return;
    }
    taint_t t = create_and_taint_fdset(nfds, fds);
    write_tokens_info(outfd, t, tci, 1);
}

void write_output_taint(int outfd, taint_t t,
                        struct taint_creation_info* tci, int offset)
{
    struct byte_result result;
    new_byte_result(&result, tci->type, tci->fileno, tci->rg_id,
                                tci->record_pid, tci->syscall_cnt,
                                tci->offset + offset, 1);
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
    int i;
    for (i = 0; i < size; i++) {
        taint_t* mem_taints;
        u_long addr = ((u_long) buf) + i;
        mem_taints = get_mem_taints(addr, 1);

        if (mem_taints) {
            int rc;
            taint_t value = mem_taints[0];
            rc = write(outfd, &addr, sizeof(u_long));
            if (rc != sizeof(u_long)) {
                fprintf(stderr, "Could not write taint addr\n");
            }
#ifdef TAINT_DEBUG
	    if (TAINT_DEBUG(value)) {
	      fprintf (debug_f, "output %lx has taint value %x buf %p addr %lx %d out of %d clock %lx\n", 
		       debug_taint_cnt, value, buf, addr, i, size, *ppthread_log_clock);
	    }
	    debug_taint_cnt++;
#endif
            rc = write(outfd, &value, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "Could not write taint value\n");
            }
        } else {
            int rc;
            taint_t value = 0;
            rc = write(outfd, &addr, sizeof(u_long));
            if (rc != sizeof(u_long)) {
                fprintf(stderr, "Could not write taint addr\n");
            }
#ifdef TAINT_DEBUG
	    debug_taint_cnt++;
#endif
            rc = write(outfd, &value, sizeof(taint_t));
            if (rc != sizeof(taint_t)) {
                fprintf(stderr, "Could not write taint value\n");
            }
        }
    }
}

int filter_outputs (struct taint_creation_info* tci)
{
    if (taint_filter_outputs) return 1;
    if (taint_filter_outputs_syscall > 0) {
	if (tci->syscall_cnt != taint_filter_outputs_syscall) {
	    return 1;
	}
    }
    return 0;
}

#ifdef USE_SHMEM
#define OUTBUFSIZE 0x1000000
static char* outputbuf = NULL;
static u_long outputindex = 0;
static u_long output_total_count = 0;
#endif

static inline void fill_outbuf (char* pout, struct taint_creation_info* tci, void* buf, int size)
{
    memcpy (pout, tci, sizeof(struct taint_creation_info));
    pout += sizeof(struct taint_creation_info);
    memcpy (pout, &buf, sizeof(u_long));
    pout += sizeof(u_long);
    memcpy (pout, &size, sizeof(int));
    pout += sizeof(int);

    for (int i = 0; i < size; i++) {
	taint_t* mem_taints;
	u_long addr = ((u_long) buf) + i;
	taint_t value;
	
	memcpy (pout, &addr, sizeof(u_long));
	pout += sizeof(u_long);
	
	mem_taints = get_mem_taints(addr, 1);
	if (mem_taints) {
	    value = mem_taints[0];
	} else {
	    value = 0;
	}
#ifdef TAINT_DEBUG
	if (TAINT_DEBUG(value)) {
	    fprintf (debug_f, "output %lx has taint value %x buf %p addr %lx %d out of %d clock %lx\n", 
		     debug_taint_cnt, value, buf, addr, i, size, *ppthread_log_clock);
	}
	debug_taint_cnt++;
#endif
	memcpy (pout, &value, sizeof(taint_t));
	pout += sizeof(taint_t);
    }
#ifdef TAINT_DEBUG
    fprintf (debug_f, "output %lx-%lx size %d clock %ld\n", 
	     debug_taint_cnt-size, debug_taint_cnt, size, *ppthread_log_clock);
#endif
}

void output_buffer_result (void* buf, int size,
			   struct taint_creation_info* tci,
			   int outfd)
{

    //this is our bs outfd.. 
    if(outfd == -99999) { 
	
	return;
    }
    if (!filter_outputs(tci)) {
#ifdef USE_NW
	struct taint_data_header hdr;
	char* outbuf;

	hdr.type = TAINT_DATA_OUTPUT;
	hdr.datasize = sizeof(struct taint_creation_info) + sizeof(u_long) + sizeof(int) +
	    size * (sizeof(u_long) + sizeof(taint_t));
	outbuf = (char *) malloc(hdr.datasize);
	if(outbuf == NULL) { 
	    fprintf(stderr,"outbut is NULL, cannot malloc size %d, errno %d\n",hdr.datasize,errno);
	}
	assert (outbuf);
	fill_outbuf (outbuf, tci, buf, size);
	long rc = write (outfd, &hdr, sizeof(hdr));
	if (rc != sizeof(hdr)) {
	    fprintf (stderr, "Cannot write nw header for output data, rc=%ld, errno=%d\n", rc, errno);
	    assert (0);
	}

	u_long bytes_written = 0;
	while (bytes_written < hdr.datasize) {
	    rc = write (outfd, (char *) outbuf+bytes_written, hdr.datasize-bytes_written);	
	    if (rc <= 0) {
		fprintf (stderr, "Cannot write output data, rc=%ld, errno=%d\n", rc, errno);
		fprintf (stderr, "already written %lu bytes, tried to write %lu\n",total_output_written, hdr.datasize-bytes_written);
		assert (0);
	    }
	    bytes_written += rc;
	    total_output_written += rc;
	}
	free(outbuf);
#endif
#ifdef USE_SHMEM
	u_long datasize = sizeof(struct taint_creation_info) + sizeof(u_long) + sizeof(int) + size * (sizeof(u_long) + sizeof(taint_t));

	if (outputbuf == NULL) {
	    outputbuf = (char *) mmap (0, OUTBUFSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, outfd, 0);
	    if (outputbuf == MAP_FAILED) {
		fprintf (stderr, "could not map output buffer, errno=%d\n", errno);
		assert (0);
	    }
	}
	// Check for overflow
	if (output_total_count+datasize >= MAX_OUT_SIZE) {
	    fprintf (stderr, "Cannot allocate any more output buffer than %ld\n", (u_long) output_total_count+datasize);
	    assert (0);
	}
	if (outputindex+datasize >= OUTBUFSIZE) {
	    // Fill in temporary buffer
	    char* outbuf = (char *) malloc(datasize);
	    assert (outbuf);
	    fill_outbuf (outbuf, tci, buf, size);
	    
	    // Copy first n bytes to the previous shmem
	    memcpy (outputbuf+outputindex, outbuf, OUTBUFSIZE-outputindex);
	    
	    // Unmap the current region
	    if (munmap (outputbuf, OUTBUFSIZE) < 0) {
		fprintf (stderr, "could not munmap dump buffer, errno=%d\n", errno);
		assert (0);
	    }
	
	    // Map in the next region
	    outputbuf = (char *) mmap (0, OUTBUFSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, 
				       outfd, output_total_count+OUTBUFSIZE-outputindex);
	    if (outputbuf == MAP_FAILED) {
		fprintf (stderr, "could not map output buffer at offset %lx, errno=%d\n", output_total_count+OUTBUFSIZE-outputindex, errno);
		assert (0);
	    }
	    
	    // Now copy last bytes to new shmem
	    memcpy (outputbuf, outbuf + (OUTBUFSIZE-outputindex), datasize - (OUTBUFSIZE-outputindex));
	    outputindex = datasize - (OUTBUFSIZE-outputindex);
	    free(outbuf);
	} else {
	    fill_outbuf (outputbuf+outputindex, tci, buf, size);
	    outputindex += datasize;
	}
	output_total_count += datasize;
#endif
#ifdef USE_FILE
        write_output_header(outfd, tci, buf, size); 
        write_output_taints(outfd, buf, size);
#endif
    }
}

#ifdef USE_SHMEM
void output_finish (int outfd)
{
    int rc = ftruncate (outfd, output_total_count);
    if (rc < 0) {
	fprintf (stderr, "Unable to truncate output shmem, rc=%d, errno=%d\n", rc, errno);
    }
    close (outfd);
}
#endif

void output_xcoords (int outfd, int syscall_cnt, 
                        int dest_x, int dest_y, u_long mem_loc)
{
    taint_t* mem_taints;
    mem_taints = get_mem_taints(mem_loc, 1);

    if (mem_taints) {
        int rc;
        rc = write(outfd, &syscall_cnt, sizeof(syscall_cnt));
        if (rc != sizeof(syscall_cnt)) {
            fprintf(stderr, "output xcoords: could not write syscall_cnt\n");
            assert(0);
        }

        rc = write(outfd, &dest_x, sizeof(dest_x));
        if (rc != sizeof(dest_x)) {
            fprintf(stderr, "output xcoords: could not write dest_x\n");
            assert(0);
        }

        rc = write(outfd, &dest_y, sizeof(dest_y));
        if (rc != sizeof(dest_y)) {
            fprintf(stderr, "output xcoords: could not write dest_y\n");
            assert(0);
        }

        rc = write(outfd, mem_taints, sizeof(taint_t));
        if (rc != sizeof(taint_t)) {
            fprintf(stderr, "output xcoords: could not write taint_t\n");
            assert(0);
        }
    }
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
	if (fif == NULL) {
		fprintf (stderr, "Unable to malloc filter input file\n");
		assert (0);
	}
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
	if (fis == NULL) {
		fprintf (stderr, "Unable to malloc filter input syscall\n");
		assert (0);
	}
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
	if (fir == NULL) {
		fprintf (stderr, "Unable to malloc filter regex\n");
		assert (0);
	}
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
	if (fbr == NULL) {
		fprintf (stderr, "Unable to malloc filter byterange\n");
		assert (0);
	}
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
    //    size_t read;
    int read;
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
