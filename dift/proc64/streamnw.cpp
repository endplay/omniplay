#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <atomic>

using namespace std;

#include "streamserver.h"
#include "streamnw.h"

long safe_read (int s, void* buf, u_long size) 
{
    long bytes_read = 0;
    
    while (bytes_read < (long) size) {
	long rc = read (s, (char *) buf+bytes_read, size-bytes_read);	
	if (rc <= 0) return rc;
	bytes_read += rc;
    }
    return bytes_read;
}

long safe_write (int s, void* buf, u_long size)
{
    long bytes_written = 0;
    
    while (bytes_written < (long) size) {
	long rc = write (s, (char *) buf+bytes_written, size-bytes_written);	
	if (rc <= 0) return rc;
	bytes_written += rc;
    }
    return bytes_written;
}

long send_file (int s, const char* pathname, const char* filename)
{
    char buf[1024*1024];
    char sendfilename[NAMELEN];
    struct stat st;
    long rc;

    // Get the filename
    int fd = open (pathname, O_RDONLY);
    if (fd < 0) {
	fprintf (stderr, "send_file: cannot open %s, rc=%d, errno=%d\n", pathname, fd, errno);
	return fd;
    }

    // Send the filename
    strcpy (sendfilename, filename);
    rc = write (s, sendfilename, sizeof(sendfilename));
    if (rc != sizeof(sendfilename)) {
	fprintf (stderr, "send_file: cannot write filename, rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }

    // Send the file stats
    rc = fstat (fd, &st);
    if (rc < 0) {
	fprintf (stderr, "send_file: cannot stat %s, rc=%ld, errno=%d\n", filename, rc, errno);
	return rc;
    }
    rc = write (s, &st, sizeof(st));
    if (rc != sizeof(st)) {
	fprintf (stderr, "send_file: cannot write file %s stats, rc=%ld, errno=%d\n", filename, rc, errno);
	return rc;
    }
	
    // Send file data
    u_long bytes_written = 0;
    while (bytes_written < (u_long) st.st_size) {
	u_long to_write = st.st_size - bytes_written;
	if (to_write > sizeof(buf)) to_write = sizeof(buf);
	rc = read (fd, buf, to_write);
	if (rc <= 0) {
	    fprintf (stderr, "send_file: read of %s returns %ld, errno=%d\n", filename, rc, errno);
	    break;
	}
	long wrc = safe_write(s, buf, rc);
	if (wrc != rc) {
	    fprintf (stderr, "send_file: write of %s returns %ld (not %ld), errno=%d\n", filename, wrc, rc, errno);
	    break;
	}
	bytes_written += rc;
    }
    close (fd);

    return rc;
}

long fetch_file (int s, const char* dest_dir)
{
    char buf[1024*1024];
    char filename[NAMELEN];
    struct stat st;
    u_long bytes_read;
    long rc;

    // Get the filename
    rc = safe_read (s, filename, sizeof(filename));
    if (rc != sizeof(filename)) {
	fprintf (stderr, "fetch_file: cannot read filename, rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }

    // Get the file stats
    rc = safe_read (s, (char *) &st, sizeof(st));
    if (rc != sizeof(st)) {
	fprintf (stderr, "fetch_file: cannot read file %s stats, rc=%ld, errno=%d\n", filename, rc, errno);
	return rc;
    }
	
    // Open the new file
    char pathname[PATHLEN];
    sprintf (pathname, "%s/%s", dest_dir, filename);
    int fd = open (pathname, O_CREAT|O_WRONLY|O_TRUNC, st.st_mode);
    if (fd < 0) {
	fprintf (stderr, "fetch_file: cannot create %s, rc=%ld, errno=%d\n", pathname, rc, errno);
	return rc;
    }
	
    // Get the file data and write it out
    bytes_read = 0;
    while (bytes_read < (u_long) st.st_size) {
	u_long to_read = st.st_size - bytes_read;
	if (to_read > sizeof(buf)) to_read = sizeof(buf);
	rc = read (s, buf, to_read);
	if (rc <= 0) {
	    fprintf (stderr, "fetch_file: read of %s returns %ld, errno=%d\n", filename, rc, errno);
	    break;
	}
	long wrc = write(fd, buf, rc);
	if (wrc != rc) {
	    fprintf (stderr, "fetch_file: write of %s returns %ld, errno=%d\n", filename, rc, errno);
	    break;
	}
	bytes_read += rc;
    }

    struct timespec times[2];
    times[0].tv_sec = st.st_mtim.tv_sec;
    times[0].tv_nsec = st.st_mtim.tv_nsec;
    times[1].tv_sec = st.st_mtim.tv_sec;
    times[1].tv_nsec = st.st_mtim.tv_nsec;
    rc = futimens (fd, times);
    if (rc < 0) {
	fprintf (stderr, "utimensat returns %ld for file %s, errno=%d\n", rc, filename, errno);
    }

    close (fd);
    return rc;
}

