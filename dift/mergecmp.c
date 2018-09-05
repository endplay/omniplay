#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define ALLOW_DUPS

#define BUFSIZE 100000

int cmp (const void* p1, const void* p2)
{
    u_long* pl1 = (u_long *) p1;
    u_long* pl2 = (u_long *) p2;
    return *pl1 - *pl2;
}

int main (int argc, char* argv[])
{
    int fd1, fd2, rc;
    u_long value1, value2, prev, entry = 0;
    struct stat st1, st2;
    u_long buf1[BUFSIZE], buf2[BUFSIZE];
    int i, outndx, bufcnt1 = 0, bufcnt2 = 0;

    if (argc < 3) {
	fprintf (stderr, "format: mergecmp [file1] [file2]\n");
	return -1;
    }

    fd1 = open (argv[1], O_RDONLY);
    if (fd1 < 0) {
	fprintf (stderr, "Cannot open %s\n", argv[1]);
	return fd1;
    }

    fd2 = open (argv[2], O_RDONLY);
    if (fd2 < 0) {
	fprintf (stderr, "Cannot open %s\n", argv[1]);
	return fd2;
    }

    rc = fstat (fd1, &st1);
    if (rc < 0) {
	fprintf (stderr, "Cannot stat %s\n", argv[1]);
	return fd1;
    }
    rc = fstat (fd2, &st2);
    if (rc < 0) {
	fprintf (stderr, "Cannot stat %s\n", argv[2]);
	return fd1;
    }
    if (st1.st_size != st2.st_size) {
	fprintf (stderr, "Files have different length\n");
    }

    do {
	
	// Read in a set from file1 
	bufcnt1 = 0;
	do {
	    rc = read (fd1, &value1, sizeof(value1));
	    if (rc != sizeof(value1)) {
		return 0;
	    }
	    if (value1) buf1[bufcnt1++] = value1;
	} while (value1);
	if (bufcnt1) qsort(buf1, bufcnt1, sizeof(u_long), cmp);
#ifdef ALLOW_DUPS
	if (bufcnt1 > 1) {
	    prev = buf1[0];
	    outndx = 1;
	    for (i = 1; i < bufcnt1; i++) {
		if (buf1[i] != prev) {
		    buf1[outndx++] = buf1[i];
		} 
		prev = buf1[i];
	    }
	    bufcnt1 = outndx;
	}
#endif

	// Read in a set from file2
	bufcnt2 = 0;
	do {
	    rc = read (fd2, &value2, sizeof(value2));
	    if (rc != sizeof(value2)) {
		return 0;
	    }
	    if (value2) buf2[bufcnt2++] = value2;
	} while (value2);
	if (bufcnt2) qsort(buf2, bufcnt2, sizeof(u_long), cmp);
#ifdef ALLOW_DUPS
	if (bufcnt2 > 1) {
	    prev = buf2[0];
	    outndx = 1;
	    for (i = 1; i < bufcnt2; i++) {
		if (buf2[i] != prev) {
		    buf2[outndx++] = buf2[i];
		} 
		prev = buf2[i];
	    }
	    bufcnt2 = outndx;
	}
#endif


	if (bufcnt1 != bufcnt2 || memcmp(buf1, buf2, bufcnt1*sizeof(u_long))) {
	    printf ("Entry %lu differs: %s has %d entries, %s has %d entries\n",
		    entry, argv[1], bufcnt1, argv[2], bufcnt2);
	    if (bufcnt1 < bufcnt2) {
		for (i = 0; i < bufcnt1; i++) {
		    printf ("(value=%lx,%lx)\n", buf1[i], buf2[i]);
		}
		for (i = bufcnt1; i < bufcnt2; i++) {
		    printf ("(value=---,%lx)\n", buf2[i]);
		}
	    } else {
		for (i = 0; i < bufcnt2; i++) {
		    printf ("(value=%lx,%lx)\n", buf1[i], buf2[i]);
		}
		for (i = bufcnt2; i < bufcnt1; i++) {
		    printf ("(value=%lx,---)\n", buf1[i]);
		}
	    }
	}
	
	entry++;
    } while (1);

    return 0;
}
