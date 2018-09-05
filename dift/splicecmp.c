#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int cmp (const void* p1, const void* p2)
{
    u_long* pl1 = (u_long *) p1;
    u_long* pl2 = (u_long *) p2;
    return *pl1 - *pl2;
}

int main (int argc, char* argv[])
{
    struct stat st, st2;
    u_long* splice1, *splice2;
    int fd, rc, i, entries1, entries2;

    if (argc < 3) {
	fprintf (stderr, "splicecmp file1 file2\n");
	return -1;
    }

    fd = open (argv[1], O_RDONLY);
    if (fd < 0) {
	fprintf (stderr, "Cannot open file %s\n", argv[1]);
	return fd;
    }
    rc = fstat (fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Cannot stat file %s\n", argv[1]);
	return rc;
    }

    splice1 = (u_long *) malloc (st.st_size);
    if (splice1 == NULL) {
	fprintf (stderr, "Unable to malloc splice buffer of size %lu\n", st.st_size);
    }


    rc = read (fd, splice1, st.st_size);
    if (rc != st.st_size) {
	fprintf (stderr, "Unable to read splice data from %s\n", argv[1]);
	return rc;
    }
    close (fd);
    entries1 = st.st_size/sizeof(u_long);
    qsort (splice1, entries1, sizeof(u_long), cmp);

    fd = open (argv[2], O_RDONLY);
    if (fd < 0) {
	fprintf (stderr, "Cannot open file %s\n", argv[2]);
	return fd;
    }
    rc = fstat (fd, &st2);
    if (rc < 0) {
	fprintf (stderr, "Cannot stat file %s\n", argv[2]);
	return rc;
    }
    splice2 = (u_long *) malloc (st2.st_size);
    if (splice2 == NULL) {
	fprintf (stderr, "Unable to malloc splice buffer of size %lu\n", st2.st_size);
    }

    rc = read (fd, splice2, st2.st_size);
    if (rc != st2.st_size) {
	fprintf (stderr, "Unable to read splice data from %s\n", argv[2]);
	return rc;
    }
    close (fd);
    entries2 = st2.st_size/sizeof(u_long);
    qsort (splice2, entries2, sizeof(u_long), cmp);

    if (entries1 > entries2) {
	for (i = 0; i < entries2; i++) {
	    if (splice1[i] != splice2[i]) {
		printf ("%d: %lx,%lx\n", i, splice1[i], splice2[i]);
	    }
	}
	for (i = entries2; i < entries1; i++) {
	    printf ("%d: %lx,---\n", i, splice1[i]);
	}
    } else {
	for (i = 0; i < entries1; i++) {
	    if (splice1[i] != splice2[i]) {
		printf ("%d: %lx,%lx\n", i, splice1[i], splice2[i]);
	    }
	}
	for (i = entries1; i < entries2; i++) {
	    printf ("%d: ---,%lx\n", i, splice2[i]);
	}
    }

    return 0;
}
