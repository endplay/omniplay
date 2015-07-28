#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "maputil.h"

int map_file (const char* filename, int* pfd, u_long* pdatasize, u_long* pmapsize, char** pbuf)
{
    struct stat st;
    u_long size;
    int fd, rc;
    char* buf;

    fd = open (filename, O_RDONLY);
    if (fd < 0) {
	fprintf (stderr, "Unable to open %s, rc=%d, errno=%d\n", filename, fd, errno);
	return fd;
    }
    rc = fstat(fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Unable to stat %s, rc=%d, errno=%d\n", filename, rc, errno);
	return rc;
    }
    if (st.st_size > 0) {
	if (st.st_size%4096) {
	    size = st.st_size + 4096-st.st_size%4096;
	} else {
	    size = st.st_size;
	}
	buf = (char *) mmap (NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
	    fprintf (stderr, "Cannot map file %s, errno=%d\n", filename, errno);
	    return -1;
	}
	*pmapsize = size;
	*pbuf = buf;
    } else {
	*pmapsize = 0;
	*pbuf = NULL;
    }
    *pfd = fd;
    *pdatasize = st.st_size;

    return 0;
}

void unmap_file (char* buf, int fd, u_long mapsize)
{
    if (buf) {
	munmap (buf, mapsize);
    }
    close (fd);
}

