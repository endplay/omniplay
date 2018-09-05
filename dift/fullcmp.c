#include <stdio.h>
#include <stdlib.h>
#include <glib-2.0/glib.h>
#include "taint_interface/taint_creation.h"
#include "maputil.h"

int main (int argc, char* argv[])
{
    char mapfile[80], resmapfile[80], mergefile[80], resmergefile[80], taintfile[80];
    int mapfd, mergefd, resmapfd, resmergefd, taintfd;
    u_long mapdatasize, mergedatasize, resmapdatasize, resmergedatasize, taintdatasize;
    u_long mapmapsize, mergemapsize, resmapmapsize, resmergemapsize, taintmapsize;
    char* mapbuf, *mergebuf, *resmapbuf, *resmergebuf, *taintbuf;
    struct taint_creation_info* tci, *tcig;
    char* pout, *pgout;
    u_long* mbuf, *mgbuf, *tout;
    u_long buf_size, buf_sizeg, i;
    long rc;
    GHashTable* mergehash;

    if (argc != 3) {
	printf ("Format: fullcmp <map dir #> <merge dir #>\n");
    }

    sprintf (mapfile, "/tmp/%s/map", argv[1]);
    sprintf (resmapfile, "/tmp/%s/dataflow.result", argv[1]);
    sprintf (mergefile, "/tmp/%s/merge", argv[2]);
    sprintf (resmergefile, "/tmp/%s/dataflow.result", argv[2]);
    sprintf (taintfile, "/tmp/%s/taint_structures", argv[2]);

    rc = map_file (resmapfile, &resmapfd, &resmapdatasize, &resmapmapsize, &resmapbuf);
    if (rc < 0) return rc;

    rc = map_file (resmergefile, &resmergefd, &resmergedatasize, &resmergemapsize, &resmergebuf);
    if (rc < 0) return rc;

    rc = map_file (mapfile, &mapfd, &mapdatasize, &mapmapsize, &mapbuf);
    if (rc < 0) return rc;

    rc = map_file (mergefile, &mergefd, &mergedatasize, &mergemapsize, &mergebuf);
    if (rc < 0) return rc;
    
    rc = map_file (taintfile, &taintfd, &taintdatasize, &taintmapsize, &taintbuf);
    if (rc < 0) return rc;

    mbuf = (u_long *) mapbuf;
    mgbuf = (u_long *) mergebuf;
    pout = resmapbuf;
    pgout = resmergebuf;
    while ((char *) pout < resmapbuf + resmapdatasize) {
	tci = (struct taint_creation_info*) pout;
	pout += sizeof(struct taint_creation_info);
	pout += sizeof(u_long); // skip bufaddr
	buf_size = *((u_long *) pout);
	pout += sizeof(u_long);
	if (tci->syscall_cnt == 0) {
	    if (pgout != resmergebuf + resmergedatasize) {
		printf ("Unexpected size of merge output file %p vs %p\n", pgout, resmergebuf+resmergedatasize);
	    }

	    // Read in merge values into hash table
	    tout = (u_long *) taintbuf;
	    mergehash = g_hash_table_new(g_direct_hash, g_direct_equal);
	    while ((char *) tout < taintbuf + taintdatasize) {
		u_long addr = *tout++;
		tout++;
		GHashTable* mhash = g_hash_table_new(g_direct_hash, g_direct_equal);
		do {
		    if (*mgbuf) {
			g_hash_table_add (mhash, GUINT_TO_POINTER(*mgbuf));
			mgbuf++;
		    } else {
			g_hash_table_insert (mergehash, GUINT_TO_POINTER(addr), mhash);
			mgbuf++;
			break;
		    }
		} while (1);
	    }

	    for (i = 0; i < buf_size; i++) {
		GHashTable* mhash = g_hash_table_new(g_direct_hash, g_direct_equal);
		GHashTable* mghash = g_hash_table_lookup (mergehash, GUINT_TO_POINTER(*(u_long *) pout));
		do {
		    if (*mbuf) {
			g_hash_table_add (mhash, GUINT_TO_POINTER(*mbuf));
			//printf ("addr %lx: %lx\n", *((u_long *)pout), *mbuf);
			mbuf++;
		    } else {
			//printf ("addr %lx\n", *((u_long *)pout));
			mbuf++;
			break;
		    }
		} while (1);
		if (g_hash_table_size (mhash)) {
		    if (mghash) {
			printf ("map values: %u merge value %u\n", g_hash_table_size(mhash), g_hash_table_size(mghash));
		    } else {
			printf ("addr %lx map values but no merge values\n", *((u_long *) pout));
		    }
		} else {
		    if (mghash && g_hash_table_size(mghash)) {
			printf ("map values: %u merge value %u\n", g_hash_table_size(mhash), g_hash_table_size(mghash));
		    }
		}
		pout += sizeof(u_long);
		pout += sizeof(u_long);
	    }
	} else {
	    tcig = (struct taint_creation_info*) pgout;
	    pgout += sizeof(struct taint_creation_info);
	    pgout += sizeof(u_long); // skip bufaddr
	    buf_sizeg = *((u_long *) pgout);
	    pgout += sizeof(u_long);

	    if (tci->syscall_cnt != tcig->syscall_cnt || buf_size != buf_sizeg) {
		printf ("mismatch in output file: syscall %lu vs %lu, bufsize %lu vs %lu\n", 
			tci->syscall_cnt, tcig->syscall_cnt, buf_size, buf_sizeg);
		return -1;
	    }
	    printf ("Syscall %lu buf size %lu\n", tci->syscall_cnt, buf_size);
	    for (i = 0; i < buf_size; i++) {
		do {
		    if (*mbuf != *mgbuf) {
			printf ("map/merge mismatch: out %lu %lx vs %lx\n", i, *mbuf, *mgbuf);
		    }
		    if (*mbuf) {
			//printf ("out %lu: %lx\n", i, *mbuf);
			mbuf++;
			mgbuf++;
		    } else {
			mbuf++;
			mgbuf++;
			break;
		    }
		} while (1);
		pout += sizeof(u_long);
		pgout += sizeof(u_long);
		pout += sizeof(u_long);
		pgout += sizeof(u_long);
	    }
	} 
    }
    
    return (0);
}
