#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>

#include <unordered_map>
#include <unordered_set>

#include "taint_interface/taint_creation.h"
#include "maputil.h"

struct token {
    int type;                  // See types above, the source of the input
    unsigned long token_num;   // Unique identifier for start of range
    unsigned long size;        // Size of range (1 for single input)
    int syscall_cnt;
    int byte_offset;
#ifdef CONFAID
    char config_token[256];    // Name of the config token
    int line_num;              // Line number
    char config_filename[256]; // Name of the config file
#else
    int fileno;                // a mapping to the corresponding file/socket that this token came from
#endif
    uint64_t rg_id;            // replay group
    int record_pid;            // record thread/process
};

//#define STATS
//#define DEBUG

#ifdef DEBUG
#define ATARGET 0x9992db1
#define TARGET 67704
#endif

#define OUTBUFSIZE 1000000
u_long outbuf[OUTBUFSIZE];
u_long outindex = 0;
int outfd;

// For parallel scan
struct pardata {
    u_long*     start_at;
    u_long*     stop_at;
    std::unordered_map<u_long,u_long *>* pmaps;
    int         start_flag;
    u_long      tokens;
    pthread_t   tid;
#ifdef STATS
    u_long lookups, hits, values, zeros, entries, nulls, adjusts, pass_throughs, virgins;
#endif
};

struct resbuf {
    u_long*        buffer;
    u_long         bufsize;
    u_long         bufindex;
    struct resbuf* next;
};

#ifdef STATS
static long ms_diff (struct timeval tv1, struct timeval tv2)
{
    return ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000);
}
#endif

static void flush_outbuf()
{
    long rc = write (outfd, outbuf, outindex*sizeof(u_long));
    if (rc != (long)(outindex*sizeof(u_long))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outindex = 0;
}

static inline void print_value (u_long value) 
{
    if (outindex == OUTBUFSIZE) flush_outbuf();
    outbuf[outindex++] = value;
}

static void format ()
{
    fprintf (stderr, "Format: merge <epoch #1> <infilename #1> <epoch #2> <infilename #2> <outfilename> [-s] [-f]\n");
    exit (0);
}

static struct resbuf* newbuf ()
{
    struct resbuf* results;

    results = (struct resbuf *) malloc(sizeof(struct resbuf));
    if (results == NULL) {
	fprintf (stderr, "Cannot allocate resbuf\n");
	exit (1);
    }
    results->buffer = (u_long *) malloc(OUTBUFSIZE*sizeof(u_long));
    if (results->buffer == NULL) {
	fprintf (stderr, "Cannot allocate results buffer\n");
	exit (1);
    }
    results->bufsize = OUTBUFSIZE;
    results->bufindex = 0;
    results->next = NULL;
    return (results);
}


// xxx - may wish to support DEBUG later
void* parscan (void* arg)
{
    struct pardata* args = (struct pardata *) arg;
    u_long* m2buf = args->start_at;
    u_long* stop_at = args->stop_at;
    int start_flag = args->start_flag;
    std::unordered_map<u_long,u_long *>* pmaps = args->pmaps;
    u_long tokens = args->tokens;
    struct resbuf* results, *curbuf;
#ifdef STATS
    u_long lookups = 0, hits = 0, values = 0, zeros = 0, entries = 0, adjusts = 0, pass_throughs = 0, virgins = 0;
#endif

    curbuf = results = newbuf();
    
    while (m2buf < stop_at) {
	do {
	    if (*m2buf) {
		if (*m2buf < 0xc0000001) {
#ifdef STATS
		    lookups++;
#endif
		    std::unordered_map<u_long,u_long*>::const_iterator maps_iter = pmaps->find(*m2buf);
		    if (maps_iter != pmaps->end()) {
#ifdef STATS
			hits++;	
#endif
			if (maps_iter->second) {
			    for (u_long* mbuf = maps_iter->second; *mbuf; mbuf++) {
				if (curbuf->bufindex == curbuf->bufsize) {
				    curbuf->next = newbuf();
				    curbuf = curbuf->next;
				}
#ifdef STATS
				values++;
#endif
				curbuf->buffer[curbuf->bufindex++] = *mbuf;
			    }
			} else {
#ifdef STATS
			    zeros++;
#endif
			    // Zero taint
			}
		    } else {
			if (start_flag) {
			    // This address has not been modified - so zero taint
#ifdef STATS
			    virgins++;
#endif
			} else {
			    // Pass through taint from prior epoch
			    if (curbuf->bufindex == curbuf->bufsize) {
				curbuf->next = newbuf();
				curbuf = curbuf->next;
			    }
#ifdef STATS
			    pass_throughs++;
#endif
			    curbuf->buffer[curbuf->bufindex++] = *m2buf;
			}
		    }
		} else {
		    // Must map to an input - so adjust numbering to reflect epoch
		    if (curbuf->bufindex == curbuf->bufsize) {
			curbuf->next = newbuf();
			curbuf = curbuf->next;
		    }
#ifdef STATS
		    adjusts++;
#endif
		    curbuf->buffer[curbuf->bufindex++] = (*m2buf)-0xc0000000+tokens;
		}
		m2buf++;
	    } else {
		m2buf++;
		break;
	    }
	} while (1);
	if (curbuf->bufindex == curbuf->bufsize) {
	    curbuf->next = newbuf();
	    curbuf = curbuf->next;
	}
#ifdef STATS
	entries++;
#endif
	curbuf->buffer[curbuf->bufindex++] = 0;
    }
#ifdef STATS
    args->lookups = lookups;
    args->hits = hits;
    args->values = values;
    args->zeros = zeros;
    args->entries = entries;
    args->adjusts = adjusts;
    args->pass_throughs = pass_throughs;
    args->virgins = virgins;
#endif
    return results;
}

int main(int argc, char** argv)
{
    char outputsfile[256], addrsfile[256], mergefileo2[256], mergefilea1[256], mergefilea2[256];
    int start_flag = 0;
    int finish_flag = 0;
    int mfd, m2fd;
    u_long mdatasize, mmapsize, m2datasize, m2mapsize, addr;
    u_long* mbuf, *m2buf, *morig;
    long rc;
    u_long tokens, tokens2;
    std::unordered_map<u_long,u_long *> maps;
    std::unordered_set<u_long> new_maps;
#ifdef DEBUG
    u_long entries = 0, first_entries;
#endif
#ifdef STATS
    char statsfile[256];
    struct timeval start_tv, read_addr_tv, write_start_tv, write_end_tv, end_tv;
    long write_time = 0;
    u_long lookups = 0, hits = 0, values = 0, zeros = 0, entries = 0, adjusts = 0, pass_throughs = 0, virgins = 0;
    u_long hash_entries = 0, null_entries = 0;
    FILE* file;
#endif
    int parallelize = 1;

    if (argc < 6) {
	format();
    }
    for (int i = 6; i < argc; i++) {
	if (!strcmp(argv[i], "-s")) start_flag = 1;
	if (!strcmp(argv[i], "-f")) finish_flag = 1;
	if (!strcmp(argv[i], "-p")) {
	    if (i+1 < argc) {
		parallelize = atoi(argv[++i]);
	    } else {
		format();
	    }
	}
    }

    sprintf (outputsfile, "/tmp/%s/merge-outputs", argv[1]);
    sprintf (addrsfile, "/tmp/%s/%s-addrs", argv[1], argv[5]);
    sprintf (mergefileo2, "/tmp/%s/merge-outputs", argv[3]);
    sprintf (mergefilea1, "/tmp/%s/%s-addrs", argv[1], argv[2]);
    sprintf (mergefilea2, "/tmp/%s/%s-addrs", argv[3], argv[4]);


#ifdef STATS
    gettimeofday(&start_tv, NULL);
#endif
#ifdef DEBUG
    char* obuf;
    u_long* optr;
    int ofd;
    u_long odatasize, omapsize;

    rc = map_file (outputsfile, &ofd, &odatasize, &omapsize, &obuf);
    if (rc < 0) return rc;

    optr = (u_long *) obuf;
    while ((u_long) optr < (u_long) obuf + odatasize) {    
	if (entries == TARGET) printf ("First half entry: %d offset %lx\n", TARGET, (u_long) optr - (u_long) obuf);
	do {
	    if (*optr) {
		if (entries == TARGET) printf ("\t value %lx\n", *optr);
		optr++;
	    } else {
		optr++;
		break;
	    }
	} while (1);
	entries++;
    }
    unmap_file (obuf, ofd, omapsize);
    printf ("First half entries: %lu\n", entries);
#endif

    // First stage - read in addr map
    outfd = open (outputsfile, O_WRONLY|O_APPEND);
    if (outfd < 0) {
	fprintf (stderr, "cannot open merge output file %s, rc=%d, errno=%d\n", outputsfile, outfd, errno);
	return outfd;
    }

    rc = map_file (mergefilea1, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    morig = mbuf;
    tokens = *mbuf;
#ifdef DEBUG
    printf ("Tokens is %lx\n", tokens);
#endif
    mbuf++;
    while ((u_long) mbuf < (u_long) morig + mdatasize) {
	addr = *mbuf;
	mbuf++;
#ifdef DEBUG
	if (addr == ATARGET) printf ("addr %lx: mbuf %lx\n", addr, *mbuf);
#endif
	if (*mbuf) {
	    maps[addr] = mbuf;
	    do {
		if (*mbuf) {
		    mbuf++;
		} else {
		    mbuf++;
		    break;
		}
	    } while (1);
#ifdef STATS
	    hash_entries++;
#endif
	} else {
	    mbuf++;
#ifdef STATS
	    null_entries++;
#endif
	    maps[addr] = NULL;
	}
    }

#ifdef DEBUG
    printf ("Entries: %ld\n", entries);
    first_entries = entries;
#endif

#ifdef STATS
    gettimeofday(&read_addr_tv, NULL);
#endif

    // Next stage - map outputs to addrs
    rc = map_file (mergefileo2, &m2fd, &m2datasize, &m2mapsize, (char **) &m2buf);
    if (rc < 0) return rc;
 
    morig = m2buf;
    if (parallelize > 1 && m2datasize > 0) {
        u_long chunk = m2datasize/(parallelize*sizeof(u_long));
	u_long* start_at = m2buf;
	struct pardata* pdata = (struct pardata *) malloc(sizeof(struct pardata)*parallelize);
	if (pdata == NULL) {
	    fprintf (stderr, "Cannot malloc pardata\n");
	    return -1;
	}
	// Spawn the threads
	for (int i = 0; i < parallelize; i++) {
	    pdata[i].start_at = start_at;
	    if (i == parallelize-1) {
		pdata[i].stop_at = (u_long *) ((u_long) m2buf + m2datasize);
	    } else {
		start_at += chunk;
		while (*(start_at-1)) start_at++; // Skip to start of new sequience
		pdata[i].stop_at = start_at;
	    }
	    pdata[i].pmaps = &maps;
	    pdata[i].start_flag = start_flag;
	    pdata[i].tokens = tokens;
	    rc = pthread_create(&pdata[i].tid, NULL, parscan, &pdata[i]);
	    if (rc < 0) {
		fprintf (stderr, "Unable to spawn parscan thread\n");
		return -1;
	    }
	}
	// Wait for them to complete and write out the data in order
	for (int i = 0; i < parallelize; i++) {
	    struct resbuf* results;
	    rc = pthread_join (pdata[i].tid, (void **) &results);
	    if (rc < 0) {
		fprintf (stderr, "Unable to join with parscan thread\n");
		return -1;
	    }
#ifdef STATS
	    lookups += pdata[i].lookups;
	    hits += pdata[i].hits;
	    values += pdata[i].values;
	    zeros += pdata[i].zeros;
	    entries += pdata[i].entries;
	    pass_throughs += pdata[i].pass_throughs;
	    adjusts += pdata[i].adjusts;
	    virgins += pdata[i].virgins;
	    gettimeofday(&write_start_tv, NULL);
#endif
	    while (results) {
		rc = write (outfd, results->buffer, results->bufindex*sizeof(u_long));
		if (rc != (long)  (results->bufindex*sizeof(u_long))) {
		    fprintf (stderr, "write of buffer segment failed, rc=%ld, errno=%d\n", rc, errno);
		    exit (rc);
		}
		results = results->next;
	    }
#ifdef STATS
	    gettimeofday(&write_end_tv, NULL);
	    write_time += ms_diff (write_end_tv, write_start_tv);
#endif
	}
    } else {	
	while ((u_long) m2buf < (u_long) morig + m2datasize) {
#ifdef DEBUG
	    if (entries == TARGET) printf ("Entry %ld (%ld) mbuf %lx offset %lx\n", entries, entries - first_entries, *m2buf, (u_long) m2buf - (u_long) morig);
#endif
	    do {
		if (*m2buf) {
#ifdef DEBUG		
		    if (entries == TARGET) printf ("\tmbuf %lx offset %lx\n", *m2buf, outindex*sizeof(u_long));
#endif
		    if (*m2buf < 0xc0000001) {
#ifdef STATS
			lookups++;
#endif
			std::unordered_map<u_long,u_long*>::const_iterator maps_iter = maps.find(*m2buf);
			if (maps_iter != maps.end()) {
#ifdef STATS
			    hits++;	
#endif
			    if (maps_iter->second) {
#ifdef STATS
				values++;
#endif
				for (mbuf = maps_iter->second; *mbuf; mbuf++) {
#ifdef DEBUG
				    if (entries == TARGET) printf ("\t\tvalue %lx offset %lx\n", *mbuf, outindex);
#endif
				    print_value(*mbuf);
				}
			    } else {
				// Zero taint
#ifdef STATS
				zeros++;
#endif
			    }
			} else {
			    if (start_flag) {
				// This address has not been modified - so zero taint
			    } else {
				// Pass through taint from prior epoch
				print_value (*m2buf);
			    }
			}
		    } else {
			// Must map to an input - so adjust numbering to reflect epoch
			print_value ((*m2buf)-0xc0000000+tokens);
		    }
		    m2buf++;
		} else {
		    m2buf++;
		    break;
		}
	    } while (1);
#ifdef DEBUG
	    entries++;
#endif
	    print_value (0);
	}

#ifdef STATS
	gettimeofday(&write_start_tv, NULL);
#endif
	flush_outbuf();
#ifdef STATS
	gettimeofday(&write_end_tv, NULL);
	write_time = ms_diff (write_end_tv, write_start_tv);
#endif

    }

    unmap_file ((char *) morig, m2fd, m2mapsize);
    close (outfd);

    if (!finish_flag) {

	// Also need to generate an addr file
	outfd = open (addrsfile, O_CREAT|O_WRONLY|O_TRUNC, 0644);
	if (outfd < 0) {
	    fprintf (stderr, "cannot open addrs file %s, rc=%d, errno=%d\n", addrsfile, outfd, errno);
	    return outfd;
	}

	rc = map_file (mergefilea2, &m2fd, &m2datasize, &m2mapsize, (char **) &m2buf);
	if (rc < 0) return rc;

	morig = m2buf;
	tokens2 = *m2buf - 0xc0000000;
#ifdef DEBUG
	printf ("tokens2: %lx m2buf %lx\n", tokens2, *m2buf);
#endif
	m2buf++;
	print_value (tokens + tokens2);
	while ((u_long) m2buf < (u_long) morig + m2datasize) {
	    addr = *m2buf;
	    m2buf++;
#ifdef DEBUG
	    if (addr == ATARGET) printf ("2: addr %lx mbuf %lx\n", addr, *m2buf);
#endif
	    print_value (addr);
	    new_maps.insert(addr);
	    if (*m2buf) {
		do {
		    if (*m2buf) {
			if (*m2buf > 0xc0000000) {
#ifdef DEBUG
			    if (addr == ATARGET) printf ("2: token %lx\n", (*m2buf)-0xc0000000+tokens);
#endif
			    print_value ((*m2buf)-0xc0000000+tokens);
			} else {
			    std::unordered_map<u_long,u_long*>::const_iterator maps_iter = maps.find(*m2buf);
			    if (maps_iter != maps.end()) {
				if (maps_iter->second) {
				    for (mbuf = maps_iter->second; *mbuf; mbuf++) {
#ifdef DEBUG
					if (addr == ATARGET) printf ("2: mbuf %lx\n", *mbuf);
#endif
					print_value (*mbuf);
				    }
				}
			    } else {
				if (start_flag) {
				    // Not found = no taint
				} else {
				    // Not modified in first epoch so same address
				    print_value(*m2buf);
				}
			    }
			}
			m2buf++;
		    } else {
			m2buf++;
			break;
		    }
		} while (1);
	    } else {
		m2buf++;
	    }
	    print_value (0);
	}

	// Need to write any values no overwritten
	std::unordered_map<u_long,u_long*>::const_iterator maps_iter;
	for (maps_iter = maps.begin(); maps_iter != maps.end(); maps_iter++) {
#ifdef DEBUG
	    if (maps_iter->first == ATARGET) printf ("addr %lx in maps\n", maps_iter->first);
#endif
	    if (!new_maps.count(maps_iter->first)) {
		print_value (maps_iter->first);
		if (maps_iter->second) {
		    for (mbuf = maps_iter->second; *mbuf; mbuf++) {
			print_value (*mbuf);
		    }
		}
		print_value (0);
	    } else {
#ifdef DEBUG
		if (maps_iter->first == ATARGET) printf ("addr %lx in new_maps\n", maps_iter->first);
#endif
	    }
	}

	unmap_file ((char *) morig, m2fd, m2mapsize);

	flush_outbuf();
	close (outfd);
    }

#ifdef STATS
    gettimeofday(&end_tv, NULL);

    sprintf (statsfile, "/tmp/%s/%s-stats", argv[1], argv[5]);
    file = fopen (statsfile, "w");
    if (!file) {
	fprintf (stderr, "Cannot open stats file %s\n", statsfile);
	return -1;
    }
    fprintf (file, "Use %d threads\n", parallelize);
    fprintf (file, "Total time:        %6ld ms\n", ms_diff (end_tv, start_tv));
    fprintf (file, "Read addr time:    %6ld ms\n", ms_diff (read_addr_tv, start_tv));
    fprintf (file, "Do outputs time:   %6ld ms\n", ms_diff (write_end_tv, read_addr_tv));
    fprintf (file, "\tWrite output time: %6ld ms\n", write_time);
    fprintf (file, "Write addr time:   %6ld ms\n\n", ms_diff (end_tv, write_end_tv));
    fprintf (file, "Null entries: %ld, hash entries: %ld\n", null_entries, hash_entries);
    fprintf (file, "Lookups: %ld hits %ld values %ld zeros %ld\n", lookups, hits, values, zeros);
    fprintf (file, "Entries: %ld adjusts %ld pass throughs %ld virgins %ld\n", 
	     entries, adjusts, pass_throughs, virgins);

    fclose (file);
#endif

    return 0;
}
