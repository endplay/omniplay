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
#include <glib-2.0/glib.h>

#include "taint_interface/taint_creation.h"
#include "xray_token.h"
#include "maputil.h"

//#define DEBUG
#ifdef DEBUG
#define ATARGET 0x809c22f
//#define TARGET 933910
#define TARGET 1507350
#endif

#define OUTBUFSIZE 1000000
u_long outbuf[OUTBUFSIZE];
u_long outindex = 0;
int outfd;

static void flush_outbuf()
{
    long rc = write (outfd, outbuf, outindex*sizeof(u_long));
    if (rc != outindex*sizeof(u_long)) {
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

int main(int argc, char** argv)
{
    char outputsfile[256], addrsfile[256], mergefileo2[256], mergefilea1[256], mergefilea2[256];
    int start_flag = 0;
    int finish_flag = 0;
    int mfd;
    u_long mdatasize, mmapsize, addr;
    u_long* mbuf, *morig;
    long rc;
    u_long i, tokens, tokens2;
    GHashTable* progenitors, *old_progenitors, *maps, *new_maps;
#ifdef UNQIUE
    GHashTable* outhash;
#endif
    GHashTableIter iter, iter2;
    gpointer key, value, key2, value2;
#ifdef DEBUG
    u_long entries = 0, first_entries;
#endif
#ifdef STATS
    struct timeval tv;
    int lookups = 0, hits = 0, values = 0;
#endif

    if (argc < 6) {
	fprintf (stderr, "Format: merge <epoch #1> <infilename #1> <epoch #2> <infilename #2> <outfilename> [-s] [-f]\n");
	return -1;
    }
    for (i = 6; i < argc; i++) {
	if (!strcmp(argv[i], "-s")) start_flag = 1;
	if (!strcmp(argv[i], "-f")) finish_flag = 1;
    }

    sprintf (outputsfile, "/tmp/%s/merge-outputs", argv[1]);
    sprintf (addrsfile, "/tmp/%s/%s-addrs", argv[1], argv[5]);
    sprintf (mergefileo2, "/tmp/%s/merge-outputs", argv[3]);
    sprintf (mergefilea1, "/tmp/%s/%s-addrs", argv[1], argv[2]);
    sprintf (mergefilea2, "/tmp/%s/%s-addrs", argv[3], argv[4]);


#ifdef UNIQUE
    outhash = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif

#ifdef STATS
    gettimeofday(&tv, NULL);
    printf ("Start time: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
#endif

    // First stage
    outfd = open (outputsfile, O_WRONLY|O_APPEND);
    if (outfd < 0) {
	fprintf (stderr, "cannot open merge output file %s, rc=%d, errno=%d\n", outputsfile, outfd, errno);
	return outfd;
    }

    rc = map_file (mergefilea1, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    morig = mbuf;
    tokens = *mbuf;
    mbuf++;
    maps = g_hash_table_new(g_direct_hash, g_direct_equal);
    while ((u_long) mbuf < (u_long) morig + mdatasize) {
	addr = *mbuf;
	mbuf++;
#ifdef DEBUG
	if (addr == ATARGET) printf ("addr %lx: mbuf %lx\n", addr, *mbuf);
#endif
	if (*mbuf) {
	    progenitors = g_hash_table_new(g_direct_hash, g_direct_equal);
	    do {
		if (*mbuf) {
		    g_hash_table_add (progenitors, GUINT_TO_POINTER(*mbuf));
		    mbuf++;
		} else {
		    mbuf++;
		    break;
		}
	    } while (1);
	    g_hash_table_insert (maps, GUINT_TO_POINTER(addr), progenitors);
	} else {
	    mbuf++;
	    g_hash_table_insert (maps, GUINT_TO_POINTER(addr), NULL);
	}
    }

    unmap_file ((char *) morig, mfd, mmapsize);

#ifdef DEBUG
    printf ("Entries: %ld\n", entries);
    first_entries = entries;
#endif

#ifdef STATS
    gettimeofday(&tv, NULL);
    printf ("2nd stage time: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
#endif

    // Last stage
    rc = map_file (mergefileo2, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;
 
    morig = mbuf;
    while ((u_long) mbuf < (u_long) morig + mdatasize) {
#ifdef DEBUG
	if (entries == TARGET) printf ("Entry %ld (%ld) mbuf %lx offset %lx\n", entries, entries - first_entries, *mbuf, (u_long) mbuf - (u_long) morig);
#endif
	do {
	    if (*mbuf) {
#ifdef DEBUG		
		if (entries == TARGET) printf ("\tmbuf %lx offset %lx\n", *mbuf, outindex*sizeof(u_long));
#endif
		if (*mbuf < 0xc0000001) {
#ifdef STATS
		    lookups++;
#endif
		    if (g_hash_table_lookup_extended(maps, GUINT_TO_POINTER(*mbuf), &key, &value)) {
#ifdef STATS
			hits++;	
#endif
			if (value) {
#ifdef STATS
			    values++;
#endif
			    progenitors = (GHashTable *) value;
			    g_hash_table_iter_init(&iter, progenitors);
			    while (g_hash_table_iter_next(&iter, &key, &value)) {
#ifdef DEBUG
				if (entries == TARGET) printf ("\t\tvalue %p offset %lx\n", key, outindex);
#endif
#ifdef UNIQUE
				g_hash_table_add (outhash, key);
#else
				print_value (GPOINTER_TO_UINT(key));
#endif
			    }
			} else {
			    // Zero taint
			}
		    } else {
			if (start_flag) {
			    // This address has not been modified - so zero taint
			} else {
			    // Pass through taint from prior epoch
			    print_value (*mbuf);
			}
		    }
		} else {
		    // Must map to an input - so adjust numbering to reflect epoch
#ifdef UNIQUE
		    g_hash_table_add (outhash, GUINT_TO_POINTER((*mbuf)-0xc0000000+tokens));
#else
		    print_value ((*mbuf)-0xc0000000+tokens);
		}
#endif
		mbuf++;
	    } else {
		mbuf++;
		break;
	    }
	} while (1);
#ifdef UNIQUE
	g_hash_table_iter_init (&iter, outhash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
	    print_value (GPOINTER_TO_UINT(key));
	}
	g_hash_table_remove_all(outhash);
#endif
#ifdef DEBUG
	entries++;
#endif
	print_value (0);
    }

    unmap_file ((char *) morig, mfd, mmapsize);

#ifdef STATS
    printf ("lookups: %d hits %d values %d\n", lookups, hits, values);
    gettimeofday(&tv, NULL);
    printf ("Preflush  time: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
#endif

    flush_outbuf();
    close (outfd);

    if (!finish_flag) {

#ifdef STATS
	gettimeofday(&tv, NULL);
	printf ("3rd stage time: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
#endif

	// Also need to generate an addr file
	outfd = open (addrsfile, O_CREAT|O_WRONLY|O_TRUNC, 0644);
	if (outfd < 0) {
	    fprintf (stderr, "cannot open addrs file %s, rc=%d, errno=%d\n", addrsfile, outfd, errno);
	    return outfd;
	}

	rc = map_file (mergefilea2, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
	if (rc < 0) return rc;

	new_maps = g_hash_table_new(g_direct_hash, g_direct_equal);
	morig = mbuf;
	tokens2 = *mbuf-0xc0000000;
	mbuf++;
	print_value (tokens + tokens2);
	while ((u_long) mbuf < (u_long) morig + mdatasize) {
	    addr = *mbuf;
	    mbuf++;
#ifdef DEBUG
	    if (addr == ATARGET) printf ("2: addr %lx mbuf %lx\n", addr, *mbuf);
#endif
	    print_value (addr);
	    g_hash_table_add(new_maps, GUINT_TO_POINTER(addr));
	    if (*mbuf) {
		progenitors = g_hash_table_new(g_direct_hash, g_direct_equal);
		do {
		    if (*mbuf) {
			if (*mbuf > 0xc0000000) {
#ifdef UNIQUE
			    g_hash_table_add (outhash, GUINT_TO_POINTER((*mbuf)-0xc0000000+tokens));
#else
			    print_value ((*mbuf)-0xc0000000+tokens);
#endif
			} else {
			    old_progenitors = (GHashTable *) g_hash_table_lookup(maps, GUINT_TO_POINTER(*mbuf));
			    if (old_progenitors) {
				g_hash_table_iter_init(&iter, old_progenitors);
				while (g_hash_table_iter_next(&iter, &key, &value)) {
#ifdef UNIQUE
				    g_hash_table_add (outhash, key);
#else
				    print_value (GPOINTER_TO_UINT(key));
#endif
				}
			    }
			}
			mbuf++;
		    } else {
			mbuf++;
			break;
		    }
		} while (1);
	    } else {
		mbuf++;
	    }
#ifdef UNIQUE
	    g_hash_table_iter_init (&iter, outhash);
	    while (g_hash_table_iter_next(&iter, &key, &value)) {
		print_value (GPOINTER_TO_UINT(key));
	    }
	    g_hash_table_remove_all(outhash);
#endif
	    print_value (0);
	}

	// Need to write any values no overwritten
	g_hash_table_iter_init (&iter, maps);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
#ifdef DEBUG
	    if (GPOINTER_TO_UINT(key) == ATARGET) printf ("addr %p in maps\n", key);
#endif
	    if (!g_hash_table_contains(new_maps, key)) {
		print_value (GPOINTER_TO_UINT(key));
		if (value) {
		    g_hash_table_iter_init (&iter2, value);
		    while (g_hash_table_iter_next(&iter2, &key2, &value2)) {
			print_value (GPOINTER_TO_UINT(key2));
		    }
		}
		print_value (0);
	    } else {
#ifdef DEBUG
		if (GPOINTER_TO_UINT(key) == ATARGET) printf ("addr %p in new_maps\n", key);
#endif
	    }
	}

	unmap_file ((char *) morig, mfd, mmapsize);

	flush_outbuf();
	close (outfd);
    }

#ifdef STATS
    gettimeofday(&tv, NULL);
    printf ("End time: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
#endif

    return 0;
}
