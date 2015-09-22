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

#define NO_DUPS
#define STATS

//#define DEBUG_TARGET(x) (x==0xc71836 || x==0x1836)
//#define DEBUG_ADDR(x) (x==0x809d37c)
#ifdef DEBUG_TARGET
FILE* debugfile;
#endif

#define OUTBUFSIZE 1000000
u_long outbuf[OUTBUFSIZE];
u_long outindex = 0;
int outfd;

u_long outubuf[OUTBUFSIZE];
u_long outuindex = 0;
int outufd;

u_long outrbuf[OUTBUFSIZE];
u_long outrindex = 0;
int outrfd;

// For parallel scan
struct resbuf {
    u_long*        buffer;
    u_long         bufindex;
    struct resbuf* next;
};

struct pardata {
    u_long*        start_at;
    u_long*        stop_at;
    std::unordered_map<u_long,u_long *>* pmaps;
    int            start_flag;
    u_long         otokens;
    pthread_t      tid;
    struct resbuf* resbuf;
    struct resbuf* uresbuf;
#ifdef STATS
    u_long lookups, hits, values, zeros, entries, nulls, adjusts, pass_throughs, virgins;
#endif
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

static void flush_outubuf()
{
    long rc = write (outufd, outubuf, outuindex*sizeof(u_long));
    if (rc != (long)(outuindex*sizeof(u_long))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outuindex = 0;
}

static inline void print_uvalue (u_long value) 
{
    if (outuindex == OUTBUFSIZE) flush_outubuf();
    outubuf[outuindex++] = value;
}

static void flush_outrbuf()
{
    long rc = write (outrfd, outrbuf, outrindex*sizeof(u_long));
    if (rc != (long)(outrindex*sizeof(u_long))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outrindex = 0;
}

static inline void print_rvalue (u_long value) 
{
    if (outrindex == OUTBUFSIZE) flush_outrbuf();
    outrbuf[outrindex++] = value;
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
    results->bufindex = 0;
    results->next = NULL;
    return (results);
}

#define PPRINT_VALUE(curbuf,val) { 			\
    if ((curbuf)->bufindex == OUTBUFSIZE) {		\
	(curbuf)->next = newbuf();			\
	(curbuf) = (curbuf)->next;			\
    }							\
    (curbuf)->buffer[(curbuf)->bufindex++] = (val);	\
} 

// xxx - may wish to support DEBUG later
void* parscan (void* arg)
{
    struct pardata* args = (struct pardata *) arg;
    u_long* m2buf = args->start_at;
    u_long* stop_at = args->stop_at;
    int start_flag = args->start_flag;
    std::unordered_map<u_long,u_long *>* pmaps = args->pmaps;
    u_long otokens = args->otokens;
    struct resbuf* resbuf, *uresbuf;
    int resolved_values, unresolved_values;
    u_long otoken;
#ifdef STATS
    u_long lookups = 0, hits = 0, values = 0, zeros = 0, entries = 0, adjusts = 0, pass_throughs = 0, virgins = 0;
#endif

    args->resbuf = resbuf = newbuf();
    args->uresbuf = uresbuf = newbuf();

    while (m2buf < stop_at) {
	otoken = *m2buf + otokens;
	m2buf++;
	while (*m2buf) {
#ifdef DEBUG_TARGET
	    if (DEBUG_TARGET(otoken)) {
		fprintf (debugfile, "\toutput %lx (otokens %lx/%lx) maps to %lx\n", 
			 otoken, otokens, otoken-otokens, *m2buf);
	    }
#endif
#ifdef STATS
	    lookups++;
#endif
	    std::unordered_map<u_long,u_long*>::const_iterator maps_iter = pmaps->find(*m2buf);
	    if (maps_iter != pmaps->end()) {
#ifdef STATS
		hits++;	
#endif
		if (maps_iter->second) {
#ifdef STATS
		    values++;
#endif
		    resolved_values = 0;
		    unresolved_values = 0;
		    for (u_long* mbuf = maps_iter->second; *mbuf; mbuf++) {
#ifdef DEBUG_TARGET
			if (DEBUG_TARGET(otoken)) {
			    fprintf (debugfile, "\toutput %lx (otokens %lx/%lx) maps to %lx via %lx\n", 
				     otoken, otokens, otoken-otokens, *mbuf, *m2buf);
			}
#endif
			if (*mbuf < 0xc0000000 && !start_flag) {
			    if (!unresolved_values) {
				PPRINT_VALUE(uresbuf, otoken);
				unresolved_values = 1;
			    }
			    PPRINT_VALUE(uresbuf, *mbuf);
			} else {
			    if (!resolved_values) {
				PPRINT_VALUE(resbuf, otoken);
				resolved_values = 1;
			    }
			    if (start_flag) {
				PPRINT_VALUE(resbuf, *mbuf);
			    } else {
				PPRINT_VALUE(resbuf, *mbuf-0xc0000000);
			    }
			}
		    }
		    if (resolved_values) PPRINT_VALUE(resbuf, 0);
		    if (unresolved_values) PPRINT_VALUE(uresbuf, 0);
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
		    // Pass through taint from prior epoch - still unresolved
		    PPRINT_VALUE (uresbuf, otoken);
		    PPRINT_VALUE (uresbuf, *m2buf);
		    PPRINT_VALUE (uresbuf, 0);
		}
	    }
	    m2buf++;
	}
	m2buf++;
#ifdef STATS
	entries++;
#endif
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
    return NULL;
}

int main(int argc, char** argv)
{
    char outputsufile[256], outputsrfile[256], addrsfile[256], mergefileo2[256], mergefilea1[256], mergefilea2[256];
    int start_flag = 0;
    int finish_flag = 0;
    int mfd, m2fd;
    u_long mdatasize, mmapsize, m2datasize, ma2datasize = 0, m2mapsize, addr;
    u_long* mbuf, *m2buf, *morig;
    long rc;
    u_long tokens, tokens2, otoken, otokens;
    std::unordered_map<u_long,u_long *> maps;
    std::unordered_set<u_long> new_maps;
#ifdef STATS
    char statsfile[256];
    struct timeval start_tv, read_addr_tv, write_start_tv, write_end_tv, passthru_start_tv, end_tv;
    long write_time = 0;
    u_long lookups = 0, hits = 0, values = 0, zeros = 0, entries = 0, adjusts = 0, pass_throughs = 0, virgins = 0;
    u_long hash_entries = 0, null_entries = 0;
    u_long addr_entries = 0, addr_resolved = 0, addr_values = 0, addr_passthru = 0;
    u_long addrmap_entries = 0, addrmap_values = 0, addrmap_passthru = 0;
    FILE* file;
#endif
    int resolved_values, unresolved_values, parallelize = 1;

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

    sprintf (outputsufile, "/tmp/%s/merge-outputs-unresolved", argv[1]);
    sprintf (outputsrfile, "/tmp/%s/merge-outputs-resolved", argv[1]);
    sprintf (addrsfile, "/tmp/%s/%s-addrs", argv[1], argv[5]);
    sprintf (mergefileo2, "/tmp/%s/merge-outputs-unresolved", argv[3]);
    sprintf (mergefilea1, "/tmp/%s/%s-addrs", argv[1], argv[2]);
    sprintf (mergefilea2, "/tmp/%s/%s-addrs", argv[3], argv[4]);

#ifdef STATS
    gettimeofday(&start_tv, NULL);
#endif

#ifdef DEBUG_TARGET
    char debugname[256];
    sprintf (debugname, "/tmp/%s/%s-debug", argv[1], argv[5]);
    debugfile = fopen (debugname, "w");
    if (debugfile == NULL) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", debugname, errno);
	return -1;
    }
#endif

    // First stage - read in addr map
    rc = map_file (mergefilea1, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    morig = mbuf;
    otokens = *mbuf;
    mbuf++;
    tokens = *mbuf;
    mbuf++;
    while ((u_long) mbuf < (u_long) morig + mdatasize) {
	addr = *mbuf;
	mbuf++;
#ifdef DEBUG_ADDR
	if (DEBUG_ADDR(addr)) {
	  fprintf (debugfile, "Address %lx in map, maps to %lx, offset %lx\n", addr, *mbuf, (u_long) mbuf - (u_long) morig);
	}
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

#ifdef STATS
    gettimeofday(&read_addr_tv, NULL);
#endif

    // Next stage - map outputs to addrs
    outufd = open (outputsufile, O_WRONLY|O_APPEND|O_LARGEFILE);
    if (outufd < 0) {
	fprintf (stderr, "cannot open %s, rc=%d, errno=%d\n", outputsufile, outufd, errno);
	return outufd;
    }
    outrfd = open (outputsrfile, O_WRONLY|O_APPEND|O_LARGEFILE);
    if (outrfd < 0) {
	fprintf (stderr, "cannot open %s, rc=%d, errno=%d\n", outputsrfile, outrfd, errno);
	return outrfd;
    }

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
	    pdata[i].otokens = otokens;
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
	    for (results = pdata[i].resbuf; results; results = results->next) {
		rc = write (outrfd, results->buffer, results->bufindex*sizeof(u_long));
		if (rc != (long)  (results->bufindex*sizeof(u_long))) {
		    fprintf (stderr, "write of buffer segment failed, rc=%ld, epected %ld, errno=%d\n", 
			     rc, results->bufindex*sizeof(u_long), errno);
		    exit (rc);
		}
	    }
	    for (results = pdata[i].uresbuf; results; results = results->next) {
		rc = write (outufd, results->buffer, results->bufindex*sizeof(u_long));
		if (rc != (long)  (results->bufindex*sizeof(u_long))) {
		    fprintf (stderr, "write of buffer segment failed, rc=%ld, epected %ld, errno=%d\n", 
			     rc, results->bufindex*sizeof(u_long), errno);
		    exit (rc);
		}
	    }
#ifdef STATS
	    gettimeofday(&write_end_tv, NULL);
	    write_time += ms_diff (write_end_tv, write_start_tv);
#endif
	}
    } else {	
	while ((u_long) m2buf < (u_long) morig + m2datasize) {
	    otoken = *m2buf + otokens;
	    m2buf++;
	    while (*m2buf) {
#ifdef DEBUG_TARGET
		if (DEBUG_TARGET(otoken)) {
		    fprintf (debugfile, "\toutput %lx (otokens %lx/%lx) maps to %lx\n", 
			     otoken, otokens, otoken-otokens, *m2buf);
		}
#endif
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
			resolved_values = 0;
			unresolved_values = 0;
			for (mbuf = maps_iter->second; *mbuf; mbuf++) {
			    if (*mbuf < 0xc0000000 && !start_flag) {
				if (!unresolved_values) {
				    print_uvalue(otoken);
				    unresolved_values = 1;
				}
				print_uvalue(*mbuf);
#ifdef DEBUG_TARGET
				if (DEBUG_TARGET(otoken)) {
				    fprintf (debugfile, "output %lx (otokens %lx/%lx) -> unresolved addr %lx\n", 
					     otoken, otokens, otoken-otokens, *mbuf);
				}
#endif
			    } else {
				if (!resolved_values) {
				    print_rvalue (otoken);
				    resolved_values = 1;
				}
				if (start_flag) {
				    print_rvalue(*mbuf);
#ifdef DEBUG_TARGET
				    if (DEBUG_TARGET(otoken)) {
					fprintf (debugfile, "output %lx (otokens %lx/%lx) -> resolved input %lx (start) via %lx\n", 
						 otoken, otokens, otoken-otokens, *mbuf, *m2buf);
				    }
#endif
				} else {
				    print_rvalue(*mbuf-0xc0000000);
#ifdef DEBUG_TARGET
				    if (DEBUG_TARGET(otoken)) {
					fprintf (debugfile, "output %lx (otokens %lx/%lx) -> resolved input %lx via %lx\n", 
						 otoken, otokens, otoken-otokens, *mbuf-0xc0000000, *m2buf);
				    }
#endif
				}
			    }
			}
			if (resolved_values) print_rvalue(0);
			if (unresolved_values) print_uvalue(0);
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
			// Pass through taint from prior epoch - still unresolved
			print_uvalue(otoken);
			print_uvalue(*m2buf);
#ifdef DEBUG_TARGET
			if (DEBUG_TARGET(otoken)) {
			    fprintf (debugfile, "output %lx (otokens %lx/%lx) -> unresolved pass through %lx, offset %lx\n", 
				     otoken, otokens, otoken-otokens, *m2buf, (u_long) m2buf - (u_long) morig);
			}
#endif
			print_uvalue (0);
		    }
		}
		m2buf++;
	    }
#ifdef STATS
	    entries++;
#endif
	    m2buf++;
	}

#ifdef STATS
	gettimeofday(&write_start_tv, NULL);
#endif
	flush_outubuf();
	flush_outrbuf();
#ifdef STATS
	gettimeofday(&write_end_tv, NULL);
	write_time = ms_diff (write_end_tv, write_start_tv);
#endif

    }

    unmap_file ((char *) morig, m2fd, m2mapsize);
    close (outufd);
    close (outrfd);

    if (!finish_flag) {

	// Also need to generate an addr file
	outfd = open (addrsfile, O_CREAT|O_WRONLY|O_TRUNC|O_LARGEFILE, 0644);
	if (outfd < 0) {
	    fprintf (stderr, "cannot open addrs file %s, rc=%d, errno=%d\n", addrsfile, outfd, errno);
	    return outfd;
	}

	rc = map_file (mergefilea2, &m2fd, &ma2datasize, &m2mapsize, (char **) &m2buf);
	if (rc < 0) return rc;

	morig = m2buf;
	printf ("read output token %lx\n", *m2buf);
	print_value (otokens + *m2buf); // Add otokens together
	printf ("write output token %lx\n", otokens + *m2buf);
	m2buf++;
	printf ("read input token %lx\n", *m2buf);
	tokens2 = *m2buf - 0xc0000000;
	printf ("write input token %lx\n", tokens+tokens2);
	print_value (tokens + tokens2);
	m2buf++;
	while ((u_long) m2buf < (u_long) morig + ma2datasize) {
	    addr = *m2buf;
	    m2buf++;
#ifdef DEBUG_ADDR
	    if (DEBUG_ADDR(addr)) {
		fprintf (debugfile, "Doing address %lx first entry %lx\n", addr, *m2buf);
	    }
#endif
#ifdef STATS
	    addr_entries++;
#endif
	    print_value (addr);
	    new_maps.insert(addr);
#ifdef NO_DUPS
	    std::unordered_set<u_long> values;
#endif
	    while (*m2buf) {
		if (*m2buf > 0xc0000000) {
#ifdef STATS
		    addr_resolved++;
#endif
#ifdef DEBUG_ADDR
		    if (DEBUG_ADDR(addr)) {
			fprintf (debugfile, "Address %lx resolves to %lx m2buf %lx tokens %lx\n", addr, *m2buf-0xc0000000+tokens, *m2buf, tokens);
		    }
#endif
#ifdef NO_DUPS
		    values.insert ((*m2buf)-0xc0000000+tokens);
#else
		    print_value ((*m2buf)-0xc0000000+tokens);
#endif
		} else {
		    std::unordered_map<u_long,u_long*>::const_iterator maps_iter = maps.find(*m2buf);
		    if (maps_iter != maps.end()) {
			if (maps_iter->second) {
			    for (mbuf = maps_iter->second; *mbuf; mbuf++) {
#ifdef STATS
				addr_values++;
#endif
#ifdef DEBUG_ADDR
				if (DEBUG_ADDR(addr)) {
				    fprintf (debugfile, "Address %lx resolves to address %lx via %lx\n", addr, *mbuf, *m2buf);
				}
#endif
#ifdef NO_DUPS
				values.insert (*mbuf);
#else
				print_value (*mbuf);
#endif
			    }
			}
		    } else {
			if (start_flag) {
			    // Not found = no taint
			} else {
			    // Not modified in first epoch so same address
#ifdef STATS
			    addr_passthru++;
#endif
#ifdef DEBUG_ADDR
			    if (DEBUG_ADDR(addr)) {
				fprintf (debugfile, "Address %lx pass through to %lx\n", addr, *m2buf);
			    }
#endif
#ifdef NO_DUPS
			    values.insert(*m2buf);
#else
			    print_value(*m2buf);
#endif
			}
		    }
		}
		m2buf++;
	    }
#ifdef NO_DUPS
	    std::unordered_set<u_long>::const_iterator values_iter;
	    for (values_iter = values.begin(); values_iter != values.end(); values_iter++) {
		print_value(*values_iter);
	    }
#endif
	    m2buf++;
	    print_value (0);
	}

#ifdef STATS
	gettimeofday(&passthru_start_tv, NULL);
#endif
	// Need to write any values no overwritten
	std::unordered_map<u_long,u_long*>::const_iterator maps_iter;
	for (maps_iter = maps.begin(); maps_iter != maps.end(); maps_iter++) {
#ifdef STATS
	    addrmap_entries++;
#endif
	    if (!new_maps.count(maps_iter->first)) {
#ifdef STATS
		addrmap_passthru++;
#endif
		print_value (maps_iter->first);
		if (maps_iter->second) {
		    for (mbuf = maps_iter->second; *mbuf; mbuf++) {
#ifdef STATS
			addrmap_values++;
#endif
#ifdef DEBUG_ADDR
			if (DEBUG_ADDR(maps_iter->first)) {
			    fprintf (debugfile, "Address %lx pass through to %lx\n", maps_iter->first, *mbuf);
			}
#endif
			print_value (*mbuf);
		    }
		}
		print_value (0);
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
    if (!finish_flag) {
	fprintf (file, "Write addr time:   %6ld ms\n", ms_diff (end_tv, write_end_tv));
	fprintf (file, "\tPass through time: %6ld ms\n", ms_diff (end_tv, passthru_start_tv));
    }
    fprintf (file, "\n\n");
    fprintf (file, "Null entries: %ld, hash entries: %ld\n", null_entries, hash_entries);
    fprintf (file, "Lookups: %ld hits %ld values %ld zeros %ld\n", lookups, hits, values, zeros);
    fprintf (file, "Entries: %ld adjusts %ld pass throughs %ld virgins %ld\n", 
	     entries, adjusts, pass_throughs, virgins);
    fprintf (file, "First addr size: %lu, second output size %lu, second addr size %lu\n", 
	     mdatasize, m2datasize, ma2datasize);
    fprintf (file, "Address entries: %lu, resolved %lu, values %lu, passthru %lu\n",
	     addr_entries, addr_resolved, addr_values, addr_passthru);
    fprintf (file, "Address map entries: %lu, passthru %lu, values %lu\n",
	     addrmap_entries, addrmap_passthru, addrmap_values);

    fclose (file);
#endif

    return 0;
}
