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
#include "maputil.h"

#define OUTBUFSIZE 1000000
u_long outbuf[OUTBUFSIZE];
u_long outindex = 0;
int outfd;

#define DEBUG
#ifdef DEBUG
#define ATARGET 0x809c22f
#define TARGET 1507350
#endif

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
    char mergeofile[256], mergeafile[256], resultsfile[256];
    int mfd, s;
    u_long mdatasize, mmapsize, all_tokens, tokens, addr;
    u_long* mbuf, *morig;
    long rc;
    GHashTable* progenitors, *old_progenitors, *maps, *new_maps;
#ifdef UNQIUE
    GHashTable* outhash;
#endif
    GHashTableIter iter;
    gpointer key, value;
#ifdef DEBUG
    u_long entries = 0;
#endif

    if (argc < 3) {
	fprintf (stderr, "Format: splice_linkage [list of splice dirs from start to end]\n");
	return -1;
    }

    sprintf (resultsfile, "/tmp/%s/mergeout", argv[1]);
    sprintf (mergeofile, "/tmp/%s/merge-outputs", argv[1]);
    sprintf (mergeafile, "/tmp/%s/merge-addrs", argv[1]);
#ifdef UNIQUE
    outhash = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif
    outfd = open (resultsfile, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (outfd < 0) {
	fprintf (stderr, "cannot open merge output file %s, rc=%d, errno=%d\n", resultsfile, outfd, errno);
	return outfd;
    }

    // First stage
    rc = map_file (mergeofile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    // xxx - could just copy this block
    morig = mbuf;
    while ((u_long) mbuf < (u_long) morig + mdatasize) {
	do {
	    if (*mbuf) {
		print_value (*mbuf);
		mbuf++;
	    } else {
		mbuf++;
		break;
	    }
	} while (1);
#ifdef DEBUG
	entries++;
#endif
	print_value (0);
    }

    unmap_file ((char *) morig, mfd, mmapsize);

    rc = map_file (mergeafile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    morig = mbuf;
    all_tokens = *mbuf; // First entries is # of tokens
    mbuf++;
    maps = g_hash_table_new(g_direct_hash, g_direct_equal);
    while ((u_long) mbuf < (u_long) morig + mdatasize) {
	addr = *mbuf;
	mbuf++;
#ifdef DEBUG
	if (addr == ATARGET) printf ("0: addr %lx: mbuf %lx\n", addr, *mbuf);
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

    // Middle stages
    for (s = 2; s < argc-1; s++) {

	sprintf (mergeofile, "/tmp/%s/merge-outputs", argv[s]);
	sprintf (mergeafile, "/tmp/%s/merge-addrs", argv[s]);

	rc = map_file (mergeofile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
	if (rc < 0) return rc;

	morig = mbuf;
	while ((u_long) mbuf < (u_long) morig + mdatasize) {
#ifdef DEBUG
	  if (entries == TARGET) printf ("%d: Entry %ld mbuf %lx offset %lx\n", s-1, entries, *mbuf, (u_long) mbuf - (u_long) morig);
#endif
	    do {
		if (*mbuf) {
#ifdef DEBUG		
		    if (entries == TARGET) printf ("\tmbuf %lx\n", *mbuf);
#endif
		    if (*mbuf < 0xc0000001) {
			progenitors = (GHashTable *) g_hash_table_lookup(maps, GUINT_TO_POINTER(*mbuf));
			if (progenitors) {
			    g_hash_table_iter_init(&iter, progenitors);
			    while (g_hash_table_iter_next(&iter, &key, &value)) {
#ifdef DEBUG
				if (entries == TARGET) printf ("\t\tvalue %p\n", key);
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
#ifdef UNIQUE
			g_hash_table_add (outhash, GUINT_TO_POINTER((*mbuf)-0xc0000000+all_tokens));
#else
			print_value ((*mbuf)-0xc0000000+all_tokens);
#endif
		    }
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

	rc = map_file (mergeafile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
	if (rc < 0) return rc;

	morig = mbuf;
	tokens = *mbuf; // First entry is # of tokens
	mbuf++;
	new_maps = g_hash_table_new(g_direct_hash, g_direct_equal);
	while ((u_long) mbuf < (u_long) morig + mdatasize) {
	    addr = *mbuf;
	    mbuf++;
#ifdef DEBUG
	    if (addr == ATARGET) printf ("%d: addr %lx: mbuf %lx\n", s-1, addr, *mbuf);
#endif
	    if (*mbuf) {
		progenitors = g_hash_table_new(g_direct_hash, g_direct_equal);
		do {
		    if (*mbuf) {
			if (*mbuf > 0xc0000000) {
			    g_hash_table_add (progenitors, GUINT_TO_POINTER(*mbuf-0xc0000000+all_tokens));
			} else {
			    old_progenitors = (GHashTable *) g_hash_table_lookup(maps, GUINT_TO_POINTER(*mbuf));
			    if (old_progenitors) {
				g_hash_table_iter_init(&iter, old_progenitors);
				while (g_hash_table_iter_next(&iter, &key, &value)) {
				    g_hash_table_add (progenitors, key);
				}
			    } else {
				// Zero taint
			    }
			}
			mbuf++;
		    } else {
			mbuf++;
			break;
		    }
		} while (1);
		g_hash_table_insert (new_maps, GUINT_TO_POINTER(addr), progenitors);
	    } else {
		mbuf++;
		g_hash_table_insert (new_maps, GUINT_TO_POINTER(addr), NULL);
	    }
	}

	unmap_file ((char *) morig, mfd, mmapsize);

	all_tokens += tokens-0xc0000000;

	// Now we need to overwrite any map sets with new values
	g_hash_table_iter_init (&iter, new_maps);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
	    GHashTable* tmp = g_hash_table_lookup (maps, key);
	    if (tmp) g_hash_table_destroy (tmp);
	    g_hash_table_insert (maps, key, value);
	}
	g_hash_table_remove_all(new_maps);
    }

    // Last stage
    sprintf (mergeofile, "/tmp/%s/merge-outputs", argv[s]);

    rc = map_file (mergeofile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    morig = mbuf;
    while ((u_long) mbuf < (u_long) morig + mdatasize) {
	do {
	    if (*mbuf) {
		if (*mbuf < 0xc0000001) {
		    progenitors = (GHashTable *) g_hash_table_lookup(maps, GUINT_TO_POINTER(*mbuf));
		    if (progenitors) {
			g_hash_table_iter_init(&iter, progenitors);
			while (g_hash_table_iter_next(&iter, &key, &value)) {
#ifdef UNIQUE
			    g_hash_table_add (outhash, key);
#else
			    print_value (GPOINTER_TO_UINT(key));
#endif
			} 
		    } else {
			// This address has not been modified - so zero taint
		    }
		} else {
#ifdef UNIQUE
		    g_hash_table_add (outhash, GUINT_TO_POINTER((*mbuf)-0xc0000000+all_tokens));
#else
		    print_value ((*mbuf)-0xc0000000+all_tokens);
#endif
		}
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
	print_value (0);
    }

    unmap_file ((char *) morig, mfd, mmapsize);

    flush_outbuf();
    close (outfd);

    return 0;
}
