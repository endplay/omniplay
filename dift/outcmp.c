#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "linkage_common.h"
#include "taint_interface/taint_creation.h"
#include "xray_token.h"

int print_details = 1;
u_long input_tokens = 0;
u_long output_tokens = 0;

int main (int argc, char* argv[])
{
    int fd1, fd2, rc, dir1, dir2, start_dir1, start_dir2;
    char filename1[80], filename2[80];
    struct taint_creation_info tci1, tci2;
    struct token tok1, tok2;
    u_long bufaddr1, bufaddr2;
    u_long bufsize1, bufsize2;
    u_long i;
    int file_offset1 = 0, file_offset2 = 0;
    u_long tok_offset1 = 0, tok_offset2 = 0;
    int last_tok_num1 = 0, last_tok_num2 = 0;

    if (argc < 4) {
	fprintf (stderr, "format: outcmp [list of dirids #1] 0 [list of dirids #2]\n");
	return -1;
    }
    
    dir1 = 1;
    dir2 = 0;
    for (i = 1; i < argc; i++) {
	if (!strcmp(argv[i], "0")) {
	    dir2 = i+1;
	}
    }
    if (dir2 == 0) {
	fprintf (stderr, "format: outcmp [list of dirids #1] 0 [list of dirids #2]\n");
	return -1;
    }
    start_dir1 = dir1;
    start_dir2 = dir2;
    
    // Start off by comparing the output files
    sprintf (filename1, "/tmp/%s/dataflow.result", argv[dir1]);
    sprintf (filename2, "/tmp/%s/dataflow.result", argv[dir2]);

    fd1 = open (filename1, O_RDONLY);
    if (fd1 < 0) {
	fprintf (stderr, "Cannot open %s\n", filename1);
	return fd1;
    }

    fd2 = open (filename2, O_RDONLY);
    if (fd2 < 0) {
	fprintf (stderr, "Cannot open %s\n", filename2);
	return fd2;
    }

    do {
	rc = read (fd1, &tci1, sizeof(struct taint_creation_info));
	if (rc == 0) break;
	if (rc != sizeof(struct taint_creation_info)) {
	    fprintf (stderr, "cannot read taint info from %s, rc=%d, errno=%d\n", argv[1], rc, errno);
	    return rc;
	}

	while (tci1.syscall_cnt == 0) {
	    // Switch to next file
	    close (fd1);
	    file_offset1 = -1;
	    dir1++;
	    sprintf (filename1, "/tmp/%s/dataflow.result", argv[dir1]);
	    fd1 = open (filename1, O_RDONLY);
	    if (fd1 < 0) {
		fprintf (stderr, "Cannot open %s\n", filename1);
		return fd1;
	    }
	    rc = read (fd1, &tci1, sizeof(struct taint_creation_info));
	    if (rc != sizeof(struct taint_creation_info)) {
		fprintf (stderr, "cannot read taint info from %s, rc=%d, errno=%d\n", argv[1], rc, errno);
		return rc;
	    }
	}

	rc = read (fd2, &tci2, sizeof(struct taint_creation_info));
	if (rc != sizeof(struct taint_creation_info) && rc != 0) {
	    fprintf (stderr, "cannot read taint info from %s, rc=%d, errno=%d\n", argv[2], rc, errno);
	}
	
	while (rc == 0 || tci2.syscall_cnt == 0) {
	    // Switch to next file
	    close (fd2);
	    file_offset2 = -1;
	    dir2++;
	    if (dir2 >= argc) {
		printf ("No more dirs in seond set\n");
		goto tokcmp;
	    }
	    if (print_details) {
		printf ("------------------------------\n");
		printf ("Epoch %s\n", argv[dir2]);
	    }
	    sprintf (filename2, "/tmp/%s/dataflow.result", argv[dir2]);
	    fd2 = open (filename2, O_RDONLY);
	    if (fd2 < 0) {
		fprintf (stderr, "Cannot open %s\n", filename2);
		return fd2;
	    }
	    rc = read (fd2, &tci2, sizeof(struct taint_creation_info));
	    if (rc != sizeof(struct taint_creation_info) && rc != 0) {
		fprintf (stderr, "cannot read taint info from %s, rc=%d, errno=%d\n", argv[dir2], rc, errno);
		return rc;
	    }
	}

	// Adjust for new files
	if (file_offset1 == -1) file_offset1 = tci2.syscall_cnt - tci1.syscall_cnt;
	if (file_offset2 == -1) file_offset2 = tci1.syscall_cnt - tci2.syscall_cnt;

	if (tci1.syscall_cnt+file_offset1 != tci2.syscall_cnt+file_offset2) {
	    printf ("Taint info does not agree: syscall %lu vs. %lu\n", tci1.syscall_cnt+file_offset1, tci2.syscall_cnt+file_offset2);
	}
	
	rc = read (fd1, &bufaddr1, sizeof(u_long));
	if (rc != sizeof(u_long)) {
	    fprintf (stderr, "cannot read buf addr from %s, rc=%d, errno=%d\n", argv[1], rc, errno);
	    return rc;
	}
	rc = read (fd2, &bufaddr2, sizeof(u_long));
	if (rc != sizeof(u_long)) {
	    fprintf (stderr, "cannot read buf addr from %s, rc=%d, errno=%d\n", argv[2], rc, errno);
	    return rc;
	}
	if (bufaddr1 != bufaddr2) {
	    printf ("Bufaddrs do not agree\n");
	}
	
	rc = read (fd1, &bufsize1, sizeof(u_long));
	if (rc != sizeof(u_long)) {
	    fprintf (stderr, "cannot read buf size from %s, rc=%d, errno=%d\n", argv[1], rc, errno);
	    return rc;
	}
	rc = read (fd2, &bufsize2, sizeof(u_long));
	if (rc != sizeof(u_long)) {
	    fprintf (stderr, "cannot read buf size from %s, rc=%d, errno=%d\n", argv[2], rc, errno);
	    return rc;
	}
	if (bufsize1 != bufsize2) {
	    printf ("Bufsizes do not agree %lu %lu\n", bufsize1, bufsize2);
	}
	if (print_details) {
	    printf ("Taint from syscall %lu addr %lx size %lx (tokens %lx to %lx)\n", tci1.syscall_cnt+file_offset1, 
		    bufaddr1, bufsize1, output_tokens+1, output_tokens+bufsize1);
	    output_tokens += bufsize1;
	}
	for (i = 0; i < bufsize1; i++) {
	    rc = read (fd1, &bufaddr1, sizeof(u_long));
	    if (rc != sizeof(u_long)) {
		fprintf (stderr, "cannot read buf addr from %s, rc=%d, errno=%d\n", argv[1], rc, errno);
		return rc;
	    }
	    rc = read (fd2, &bufaddr2, sizeof(u_long));
	    if (rc != sizeof(u_long)) {
		fprintf (stderr, "cannot read buf addr from %s, rc=%d, errno=%d\n", argv[2], rc, errno);
		return rc;
	    }
	    if (bufaddr1 != bufaddr2) {
		printf ("Addrs at slot %lu do not agree\n", i);
	    }
	    rc = read (fd1, &bufaddr1, sizeof(u_long));
	    if (rc != sizeof(u_long)) {
		fprintf (stderr, "cannot read buf addr from %s, rc=%d, errno=%d\n", argv[1], rc, errno);
		return rc;
	    }
	    rc = read (fd2, &bufaddr2, sizeof(u_long));
	    if (rc != sizeof(u_long)) {
		fprintf (stderr, "cannot read buf addr from %s, rc=%d, errno=%d\n", argv[2], rc, errno);
		return rc;
	    }
	    // Values should not agree
	}
    } while (1);

    close (fd1);
    close (fd2);

  tokcmp:
    dir1 = start_dir1;
    dir2 = start_dir2;
    file_offset1 = 0;
    file_offset2 = 0;

    // Now let's compare the input files
    sprintf (filename1, "/tmp/%s/tokens", argv[dir1]);
    sprintf (filename2, "/tmp/%s/tokens", argv[dir2]);

    fd1 = open (filename1, O_RDONLY);
    if (fd1 < 0) {
	fprintf (stderr, "Cannot open %s\n", filename1);
	return fd1;
    }

    fd2 = open (filename2, O_RDONLY);
    if (fd2 < 0) {
	fprintf (stderr, "Cannot open %s\n", filename2);
	return fd2;
    }

    do {
	do {
	    rc = read (fd1, &tok1, sizeof(struct token));

	    if (rc == 0 && dir1 < start_dir2-2) {
		// Switch to next file
		close (fd1);
		file_offset1 = -1;
		tok_offset1 = 0xc0000000-last_tok_num1;
		dir1++;
		sprintf (filename1, "/tmp/%s/tokens", argv[dir1]);
		fd1 = open (filename1, O_RDONLY);
		if (fd1 < 0) {
		    fprintf (stderr, "Cannot open %s\n", filename1);
		    return fd1;
		}
	    } else {
		break;
	    }
	} while (1);
	if (rc != sizeof(struct token)) {
	    fprintf (stderr, "cannot read token from %s, rc=%d, errno=%d\n", filename1, rc, errno);
	}

	do {
	    rc = read (fd2, &tok2, sizeof(struct token));
	    if (rc == 0 && dir2 < argc-1) {
		// Switch to next file
		close (fd2);
		tok_offset2 = 0xc0000000-last_tok_num2;
		file_offset2 = -1;
		dir2++;
		if (print_details) {
		    printf ("------------------------------\n");
		    printf ("Epoch %s\n", argv[dir2]);
		}
		sprintf (filename2, "/tmp/%s/tokens", argv[dir2]);
		fd2 = open (filename2, O_RDONLY);
		if (fd2 < 0) {
		    fprintf (stderr, "Cannot open %s\n", filename2);
		    return fd2;
		}
	    } else {
		break;
	    }
	} while (1);

	if (rc != sizeof(struct token)) {
	    fprintf (stderr, "cannot read token from %s, rc=%d, errno=%d\n", filename2, rc, errno);
	    return rc;
	}

	// Adjust for new files
	if (file_offset1 == -1) file_offset1 = tok2.syscall_cnt - tok1.syscall_cnt;
	if (file_offset2 == -1) {
	    file_offset2 = tok1.syscall_cnt - tok2.syscall_cnt;
	}

	if (tok1.token_num-tok_offset1 != tok2.token_num-tok_offset2 ||
	    tok1.size != tok2.size ||
	    tok1.syscall_cnt+file_offset1 != tok2.syscall_cnt+file_offset2 ||
	    tok1.byte_offset != tok2.byte_offset) {
	    printf ("Tokens do not agree\n");
	    printf ("Token 1 number %lu size %lu syscall %d byte %d\n", tok1.token_num-tok_offset1, tok1.size, tok1.syscall_cnt+file_offset1, tok1.byte_offset);
	    printf ("Token 2 number %lu size %lu syscall %d byte %d\n", tok2.token_num-tok_offset2, tok2.size, tok2.syscall_cnt+file_offset2, tok2.byte_offset);
	    printf ("Token 1 raw syscall %d offset %d\n", tok1.syscall_cnt, file_offset1);
	    printf ("Token 2 raw syscall %d offset %d\n", tok2.syscall_cnt, file_offset2);
	} else {
	    if (print_details) {
		printf ("Token from syscall %d number %lx size %lx byte offset %d tokens from %lx to %lx\n", tok1.syscall_cnt+file_offset1, 
			tok1.token_num-tok_offset1, tok1.size, tok1.byte_offset, input_tokens+1, input_tokens+tok1.size);
		input_tokens += tok1.size;
	    }
	    last_tok_num1 = tok1.token_num+tok1.size-1-tok_offset1;
	    last_tok_num2 = tok2.token_num+tok2.size-1-tok_offset2;
	} 
    } while (1);

    return 0;
}
    
