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
    struct token token;
    char mergefile[256], outfile[256], resultsfile[256], tokfile[256], tsfile[256];
    int mfd, ofd, tfd, tsfd, s;
    u_long odatasize, omapsize, mdatasize, mmapsize, tsdatasize, tsmapsize;
    u_long* mbuf, *morig;
    char* obuf, *pout, *tsbuf;
    u_long* tsout;
    long rc;
    u_long buf_size, i, tokens;
    GHashTable* progenitors, *old_progenitors, *maps, *new_maps;
#ifdef UNQIUE
    GHashTable* outhash;
#endif
    GHashTableIter iter;
    gpointer key, value;
    struct stat st;

    if (argc < 3) {
	fprintf (stderr, "Format: splice_linkage [list of splice dirs from start to end]\n");
	return -1;
    }

    sprintf (resultsfile, "/tmp/%s/mergeout", argv[1]);
    sprintf (mergefile, "/tmp/%s/merge", argv[1]);
    sprintf (outfile, "/tmp/%s/dataflow.result", argv[1]);
    sprintf (tokfile, "/tmp/%s/tokens", argv[1]);
    sprintf (tsfile, "/tmp/%s/taint_structures", argv[1]);
#ifdef UNIQUE
    outhash = g_hash_table_new(g_direct_hash, g_direct_equal);
#endif
    outfd = open (resultsfile, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (outfd < 0) {
	fprintf (stderr, "cannot open merge output file %s, rc=%d, errno=%d\n", resultsfile, outfd, errno);
	return outfd;
    }

    // First stage
    rc = map_file (mergefile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;
    rc = map_file (outfile, &ofd, &odatasize, &omapsize, &obuf);
    if (rc < 0) return rc;

    morig = mbuf;
    pout = obuf;
    while (pout < obuf + odatasize) {
	pout += sizeof(struct taint_creation_info);
	pout += sizeof(u_long); // skip bufaddr
	buf_size = *((u_long *) pout);
	pout += sizeof(u_long);
	for (i = 0; i < buf_size; i++) {
	    do {
		if (*mbuf) {
		    print_value (*mbuf);
		    mbuf++;
		} else {
		    mbuf++;
		    break;
		}
	    } while (1);
	    print_value (0);
	    pout += sizeof(u_long);
	    pout += sizeof(u_long);
	}
    }

    unmap_file (obuf, ofd, omapsize);

    rc = map_file (tsfile, &tsfd, &tsdatasize, &tsmapsize, &tsbuf);
    if (rc < 0) return rc;

    tsout = (u_long *) tsbuf;
    maps = g_hash_table_new(g_direct_hash, g_direct_equal);
    while ((char *) tsout < tsbuf + tsdatasize) {
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
	g_hash_table_insert (maps, GUINT_TO_POINTER(*tsout), progenitors);
	tsout += 2;
    }

    unmap_file (tsbuf, tsfd, tsmapsize);
    unmap_file ((char *) morig, mfd, mmapsize);

    tfd = open (tokfile, O_RDONLY);
    if (outfd < 0) {
	fprintf (stderr, "cannot open token file %s, rc=%d, errno=%d\n", tokfile, tfd, errno);
	return tfd;
    }
    
    rc = fstat (tfd, &st);
    if (rc < 0) {
	fprintf (stderr, "Unable to fstat token file %s, rc=%ld, errno=%d\n", tokfile, rc, errno);
	return rc;
    }

    if (st.st_size > 0) {
	rc = pread (tfd, &token, sizeof(token), st.st_size-sizeof(token));
	if (rc != sizeof(token)) {
	    fprintf (stderr, "Unable to read last token from file %s, rc=%ld, errno=%d\n", tokfile, rc, errno);
	    return rc;
	}
	
	tokens = token.token_num+token.size-1;
    } else {
	tokens = 0;
    }
    close (tfd);

    // Middle stages
    for (s = 2; s < argc-1; s++) {

	sprintf (mergefile, "/tmp/%s/merge", argv[s]);
	sprintf (outfile, "/tmp/%s/dataflow.result", argv[s]);
	sprintf (tokfile, "/tmp/%s/tokens", argv[s]);
	sprintf (tsfile, "/tmp/%s/taint_structures", argv[s]);

	rc = map_file (outfile, &ofd, &odatasize, &omapsize, &obuf);
	if (rc < 0) return rc;

	rc = map_file (mergefile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
	if (rc < 0) return rc;

	morig = mbuf;
	pout = obuf;
	while (pout < obuf + odatasize) {
	    pout += sizeof(struct taint_creation_info);
	    pout += sizeof(u_long); // skip bufaddr
	    buf_size = *((u_long *) pout);
	    pout += sizeof(u_long);
	    for (i = 0; i < buf_size; i++) {
		do {
		    if (*mbuf) {
			if (*mbuf < 0xc0000001) {
			    progenitors = (GHashTable *) g_hash_table_lookup(maps, GUINT_TO_POINTER(*mbuf));
			    if (progenitors) {
				if (g_hash_table_size(progenitors)) {
				    g_hash_table_iter_init(&iter, progenitors);
				    while (g_hash_table_iter_next(&iter, &key, &value)) {
#ifdef UNIQUE					    
					g_hash_table_add (outhash, key);
#else
					print_value (GPOINTER_TO_UINT(key));
#endif
				    }
				} 
			    } else {
				// This addr has never been modified - so zero taint
			    }
			} else {
#ifdef UNIQUE
			    g_hash_table_add (outhash, GUINT_TO_POINTER((*mbuf)-0xc0000000+tokens));
#else
			    print_value ((*mbuf)-0xc0000000+tokens);
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
		
		pout += sizeof(u_long);
		pout += sizeof(u_long);
	    }
	}

	unmap_file (obuf, ofd, omapsize);

	rc = map_file (tsfile, &tsfd, &tsdatasize, &tsmapsize, &tsbuf);
	if (rc < 0) return rc;
	
	tsout = (u_long *) tsbuf;
	new_maps = g_hash_table_new(g_direct_hash, g_direct_equal);
	while ((char *) tsout < tsbuf + tsdatasize) {
	    progenitors = g_hash_table_new(g_direct_hash, g_direct_equal);
	    do {
		if (*mbuf) {
		    if (*mbuf > 0xc0000000) {
			g_hash_table_add (progenitors, GUINT_TO_POINTER(*mbuf-0xc0000000+tokens));
		    } else {
			old_progenitors = (GHashTable *) g_hash_table_lookup(maps, GUINT_TO_POINTER(*mbuf));
			if (old_progenitors) {
			    if (g_hash_table_size(old_progenitors)) {
				g_hash_table_iter_init(&iter, old_progenitors);
				while (g_hash_table_iter_next(&iter, &key, &value)) {
				    g_hash_table_add (progenitors, key);
				}
			    } 
			} else {
			    // This addr has never been modified - so zero taint
			}
		    }
		    mbuf++;
		} else {
		    mbuf++;
		    break;
		}
	    } while (1);
	    g_hash_table_insert (new_maps, GUINT_TO_POINTER(*tsout), progenitors);
	    tsout += 2;
	}

	unmap_file (tsbuf, tsfd, tsmapsize);
	unmap_file ((char *) morig, mfd, mmapsize);

	tfd = open (tokfile, O_RDONLY);
	if (outfd < 0) {
	    fprintf (stderr, "cannot open token file %s, rc=%d, errno=%d\n", tokfile, tfd, errno);
	    return tfd;
	}
	
	rc = fstat (tfd, &st);
	if (rc < 0) {
	    fprintf (stderr, "Unable to fstat token file %s, rc=%ld, errno=%d\n", tokfile, rc, errno);
	    return rc;
	}
	
	if (st.st_size > 0) {
	    rc = pread (tfd, &token, sizeof(token), st.st_size-sizeof(token));
	    if (rc != sizeof(token)) {
		fprintf (stderr, "Unable to read last token from file %s, rc=%ld, errno=%d\n", tokfile, rc, errno);
		return rc;
	    }
	    
	    tokens += token.token_num-0xc0000000+token.size-1;
	}

	close (tfd);

	// Now we need to overwrite any map sets with new values
	g_hash_table_iter_init (&iter, new_maps);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
	    GHashTable* tmp = g_hash_table_lookup (maps, key);
	    if (tmp) {
		g_hash_table_remove_all (tmp);
		g_hash_table_destroy (tmp);
	    }
	    g_hash_table_insert (maps, key, value);
	}
	g_hash_table_remove_all(new_maps);
    }

    // Last stage
    sprintf (mergefile, "/tmp/%s/merge", argv[s]);
    sprintf (outfile, "/tmp/%s/dataflow.result", argv[s]);

    rc = map_file (outfile, &ofd, &odatasize, &omapsize, &obuf);
    if (rc < 0) return rc;

    rc = map_file (mergefile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    morig = mbuf;
    pout = obuf;
    while (pout < obuf + odatasize) {
	pout += sizeof(struct taint_creation_info);
	pout += sizeof(u_long); // skip bufaddr
	buf_size = *((u_long *) pout);
	pout += sizeof(u_long);
	for (i = 0; i < buf_size; i++) {
	    do {
		if (*mbuf) {
		    if (*mbuf < 0xc0000001) {
			  progenitors = (GHashTable *) g_hash_table_lookup(maps, GUINT_TO_POINTER(*mbuf));
			  if (progenitors) {
			      if (g_hash_table_size(progenitors)) {
				  g_hash_table_iter_init(&iter, progenitors);
				  while (g_hash_table_iter_next(&iter, &key, &value)) {
#ifdef UNIQUE
				      g_hash_table_add (outhash, key);
#else
				      print_value (GPOINTER_TO_UINT(key));
#endif
				  }
			      } 
			  } else {
			      // This address has not been modified - so zero taint
			  }
		    } else {
#ifdef UNIQUE
			g_hash_table_add (outhash, GUINT_TO_POINTER((*mbuf)-0xc0000000+tokens));
#else
			print_value ((*mbuf)-0xc0000000+tokens);
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
	    pout += sizeof(u_long);
	    pout += sizeof(u_long);
	}
    }

    unmap_file ((char *) morig, mfd, mmapsize);
    unmap_file (obuf, ofd, omapsize);

    flush_outbuf();
    close (outfd);

    return 0;
}
