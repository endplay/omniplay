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

#include <unordered_set>
#include <unordered_map>

#include "taint_interface/taint.h"
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
    if (rc != (long) (outindex*sizeof(u_long))) {
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
    struct taint_creation_info* tci;
    struct token token;
    char mapfile[256], outfile[256], mergefile[256], tokfile[256];
    int mfd, ofd, tfd, s;
    u_long odatasize, omapsize, mdatasize, mmapsize;
    u_long* mbuf;
    char* obuf, *pout;
    long rc;
    u_long buf_size, i, tokens;
    std::unordered_map<u_long, std::unordered_set<u_long>*>* maps;
    std::unordered_map<u_long, std::unordered_set<u_long>*>* new_maps;
    std::unordered_set<u_long>* progenitors;
    std::unordered_set<u_long>* old_progenitors;
#ifdef UNQIUE
    std::unordered_set<u_long> outhash;
#endif
    struct stat st;

    if (argc < 3) {
	fprintf (stderr, "Format: splice_linkage [list of splice dirs from start to end]\n");
	return -1;
    }

    sprintf (mergefile, "/tmp/%s/mergeout", argv[1]);
    sprintf (mapfile, "/tmp/%s/map", argv[1]);
    sprintf (outfile, "/tmp/%s/dataflow.result", argv[1]);
    sprintf (tokfile, "/tmp/%s/tokens", argv[1]);

    outfd = open (mergefile, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (outfd < 0) {
	fprintf (stderr, "cannot open merge output file %s, rc=%d, errno=%d\n", mergefile, outfd, errno);
	return outfd;
    }

    // First stage
    rc = map_file (outfile, &ofd, &odatasize, &omapsize, &obuf);
    if (rc < 0) return rc;

    rc = map_file (mapfile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    maps = new std::unordered_map<u_long, std::unordered_set<u_long>*>;

    pout = obuf;
    while (pout < obuf + odatasize) {
	tci = (struct taint_creation_info*) pout;
	pout += sizeof(struct taint_creation_info);
	pout += sizeof(u_long); // skip bufaddr
	buf_size = *((u_long *) pout);
	pout += sizeof(u_long);
	if (tci->syscall_cnt) {
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
		pout += sizeof(taint_t);
	    }
	} else {
	    for (i = 0; i < buf_size; i++) {
		progenitors = new std::unordered_set<u_long>;
		do {
		    if (*mbuf) {
			progenitors->insert(*mbuf);
			mbuf++;
		    } else {
			mbuf++;
			break;
		    }
		} while (1);
		(*maps)[*(u_long *) pout] = progenitors;
		pout += sizeof(u_long);
		pout += sizeof(taint_t);
	    }
	}
    }

    unmap_file ((char *) mbuf, mfd, mmapsize);
    unmap_file (obuf, ofd, omapsize);

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

	new_maps = new std::unordered_map<u_long, std::unordered_set<u_long>*>;

	sprintf (mapfile, "/tmp/%s/map", argv[s]);
	sprintf (outfile, "/tmp/%s/dataflow.result", argv[s]);
	sprintf (tokfile, "/tmp/%s/tokens", argv[s]);

	rc = map_file (outfile, &ofd, &odatasize, &omapsize, &obuf);
	if (rc < 0) return rc;

	rc = map_file (mapfile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
	if (rc < 0) return rc;

	pout = obuf;
	while (pout < obuf + odatasize) {
	    tci = (struct taint_creation_info*) pout;
	    pout += sizeof(struct taint_creation_info);
	    pout += sizeof(u_long); // skip bufaddr
	    buf_size = *((u_long *) pout);
	    pout += sizeof(u_long);
	    if (tci->syscall_cnt) {
		for (i = 0; i < buf_size; i++) {
		    do {
			if (*mbuf) {
			    if (*mbuf < 0xc0000001) {
				std::unordered_map<u_long, std::unordered_set<u_long>*>::const_iterator maps_iter = maps->find(*mbuf);
				if (maps_iter != maps->end() && maps_iter->second) {
				    progenitors = maps_iter->second;
				    if (progenitors->size()) {
					std::unordered_set<u_long>::const_iterator iter;
					for (iter = progenitors->begin(); iter != progenitors->end(); iter++) {
#ifdef UNIQUE					    
					    outhash.insert(*iter);
#else
					    print_value (*iter);
#endif
					}
				    } 
				} else {
				    printf ("NULL %d\n", s);
				    exit (-1);
				}
			    } else {
#ifdef UNIQUE
				outhash.insert ((*mbuf)-0xc0000000+tokens);
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
		    std::unordered_set<u_long>::const_iterator iter;
		    for (iter = outhash.begin(); iter != outhash.end(); iter++) {
			print_value (*iter);
		    }
		    outhash.clear();
#endif
		    print_value (0);
		    
		    pout += sizeof(u_long);
		    pout += sizeof(u_long);
		}
	    } else {
		for (i = 0; i < buf_size; i++) {
		    progenitors = new std::unordered_set<u_long>;
		    do {
			if (*mbuf) {
			    if (*mbuf > 0xc0000000) {
				progenitors->insert (*mbuf-0xc0000000+tokens);
			    } else {
				std::unordered_map<u_long, std::unordered_set<u_long>*>::const_iterator maps_iter = maps->find(*mbuf);
				if (maps_iter != maps->end() && maps_iter->second) {
				    old_progenitors = maps_iter->second;
				    if (old_progenitors->size()) {
					std::unordered_set<u_long>::const_iterator iter;
					for (iter = old_progenitors->begin(); iter != old_progenitors->end(); iter++) {
					    progenitors->insert (*iter);
					}
				    } 
				} else {
				    printf ("NULL %d\n", s);
				    exit (-1);
				}
			    }
			    mbuf++;
			} else {
			    mbuf++;
			    break;
			}
		    } while (1);
		    (*new_maps)[*(u_long *) pout] = progenitors;
		    pout += sizeof(u_long);
		    pout += sizeof(u_long);
		}
	    }
	}

	unmap_file ((char *) mbuf, mfd, mmapsize);
	unmap_file (obuf, ofd, omapsize);

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

	maps = new_maps;
    }

    // Last stage
    sprintf (mapfile, "/tmp/%s/map", argv[s]);
    sprintf (outfile, "/tmp/%s/dataflow.result", argv[s]);

    rc = map_file (outfile, &ofd, &odatasize, &omapsize, &obuf);
    if (rc < 0) return rc;

    rc = map_file (mapfile, &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

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
			std::unordered_map<u_long, std::unordered_set<u_long>*>::const_iterator maps_iter = maps->find(*mbuf);
			if (maps_iter != maps->end() && maps_iter->second) {
			    progenitors = maps_iter->second;
			    if (progenitors->size()) {
				std::unordered_set<u_long>::const_iterator iter;
				for (iter = progenitors->begin(); iter != progenitors->end(); iter++) {
#ifdef UNIQUE
				    outhash.insert (*iter);
#else
				    print_value (*iter);
#endif
				}
			    } 
			} else {
			    printf ("NULL\n");
			    exit (-1);
			}
		    } else {
#ifdef UNIQUE
			outhash.insert ((*mbuf)-0xc0000000+tokens);
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
	    std::unordered_set<u_long>::const_iterator iter;
	    for (iter = outhash.begin(); iter != outhash.end(); iter++) {
		print_value (*iter);
	    }
	    outhash.clear();
#endif
	    print_value (0);
	    pout += sizeof(u_long);
	    pout += sizeof(u_long);
	}
    }

    unmap_file ((char *) mbuf, mfd, mmapsize);
    unmap_file (obuf, ofd, omapsize);

    flush_outbuf();
    close (outfd);

    return 0;
}
