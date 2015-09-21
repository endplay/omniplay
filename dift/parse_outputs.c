#include <stdio.h>
#include "xray_token.h"
#include "taint_interface/taint_creation.h"

void print_token(struct token* token) {
    fprintf(stdout, "%d %lu %lu %d %d %d %lld %d\n",
        token->type,
        token->token_num,
        token->size,
        token->syscall_cnt,
        token->byte_offset,
        token->fileno,
        token->rg_id,
        token->record_pid);
}

void print_taint_header(struct taint_creation_info* tci) {
    fprintf(stdout, "%d %lld %d %lu %d %d\n",
	    tci->type,
	    tci->rg_id,
	    tci->record_pid,
	    tci->syscall_cnt,
	    tci->offset,
	    tci->fileno);
}

void print_taint_data(u_long* buff,u_long buff_size) { 
	int i;
	for(i = 0; i < buff_size; i+=2) { 
		fprintf(stdout, "\t%lu, %lu\n",buff[i], buff[i+1]);
		buff++;
		buff++; 
	}
}

int read_taint_header(FILE* fp, struct taint_creation_info* tci) { 

    int rc;
    rc = read(fileno(fp), tci, sizeof(struct taint_creation_info));
    if (rc != sizeof(struct taint_creation_info)) {
        fprintf(stderr, "[ERROR] Could not read token from file, got %d\n", rc);
        return -1;
    }
    return 0;

}

int read_taint_data(FILE* fp, u_long* buff_size, u_long* buff) { 
	//assume that the taint header has already been read 
	u_long garbage; 
	int rc, size; 

	rc = read(fileno(fp), &garbage, sizeof(u_long));
	if (rc != sizeof(u_long)) {
		fprintf(stderr, "parse_outputs: expected to read u_long size %d, got %d\n",
			sizeof(u_long), rc);
		return -1;
	}

	rc = read(fileno(fp), buff_size, sizeof(int));
	if (rc != sizeof(int)) {
		fprintf(stderr, "parse_outputs: expected to read u_long size %d, got %d\n",
			sizeof(int), rc);
		return -1;
	}

	//I'm not actualy certain about that cast. seems way wrong
	
	size = *(buff_size) * (2 * sizeof(u_long));
	rc = read(fileno(fp), buff, size); 
	if (rc != size) {
		fprintf(stderr, "parse_outputs: expected to read u_long size %d, got %d\n",
			size, rc);
		return -1;
	}

	return 0;
}
int read_tokens_file(char* filename) {
    int fd;
    int rc;
    struct stat buf;
    FILE* fp;
    off_t count = 0;

    fd = open(filename, O_RDONLY);
    if (fd <= 0) {
        fprintf(stderr, "could not open %s, %d\n", filename, fd);
        return -1;
    }

    rc = fstat(fd, &buf);
    if (rc < 0) {
        fprintf(stderr, "could not stat file, %d\n", fd);
        return -1;
    }

    if (buf.st_size % (sizeof(struct token))) {
        fprintf(stderr, "file size is %ld, token size is %d\n",
                buf.st_size, sizeof(struct token));
    }
    assert (buf.st_size % (sizeof(struct token)) == 0);

    fp = fdopen(fd, "r");
    if (!fp) {
        fprintf(stderr, "could not get file pointer\n");
        return -1;
    }

    fprintf(stdout, "type token_num size syscall_cnt byte_offset fileno rg_id record_pid\n");

    while (count < buf.st_size) {
        struct token* token;
        token = (struct token *) malloc(sizeof(struct token));
        if (token == NULL) {
            fprintf (stderr, "Unable to malloc token\n");
            assert (0);
        }
        if (read_token_from_file(fp, token)) {
            fprintf(stderr, "could not read token, count is %lu\n", count);
        }
	print_token(token);
        count += sizeof(struct token);
    }
    return 0;
}

int read_dataflow_file(char* filename) {
    int fd;
    int rc;
    struct stat buf;
    FILE* fp;
    off_t count = 0;

    fd = open(filename, O_RDONLY);
    if (fd <= 0) {
        fprintf(stderr, "could not open %s, %d\n", filename, fd);
        return -1;
    }

    rc = fstat(fd, &buf);
    if (rc < 0) {
        fprintf(stderr, "could not stat file, %d\n", fd);
        return -1;
    }
//    if (buf.st_size % (sizeof(struct taint_creation_info))) {
        fprintf(stderr, "file size is %ld, token size is %d\n",
                buf.st_size, sizeof(struct taint_creation_info));
//    }
//    assert (buf.st_size % (sizeof(struct taint_creation_info)) == 0);

    fp = fdopen(fd, "r");
    if (!fp) {
        fprintf(stderr, "could not get file pointer\n");
        return -1;
    }

//    fprintf(stdout, "type token_num size syscall_cnt byte_offset fileno rg_id record_pid\n");
    fprintf(stdout, "type rg_id record_pid syscall_cnt offset fileno");

    while (count < buf.st_size) {
	u_long buff_size;
	u_long  buff[BUFFER_SIZE_MAX];
        struct taint_creation_info* tci;
        tci = (struct taint_creation_info *) malloc(sizeof(struct taint_creation_info));
        
	if (tci == NULL) {
            fprintf (stderr, "Unable to malloc token\n");
            assert (0);
        }
        if (read_taint_header(fp, tci)) {
            fprintf(stderr, "could not read token, count is %lu\n", count);
        }	
	print_taint_header(tci);
	//next piece is buffaddr... which doesn't matter
	

	if(read_taint_data(fp, &buff_size, buff)) { 
           fprintf(stderr, "could nont read token, count is %lu\n", count);
	}
	print_taint_data(buff, buff_size);
	
	
        count += sizeof(struct taint_creation_info);
	//also need to advance count for each of the bytes in the buffer_len? 

	count += sizeof(u_long);
	count += sizeof(int);
	count += (buff_size * 2 * sizeof(u_long));//stuff from read_taint_data
    }
    return 0;
}

int print_filename_mappings(char* filename)
{
    int fd;
    int rc;
    struct stat buf;
    FILE* fp;
    off_t count = 0;

    fd = open(filename, O_RDONLY);
    if (fd <= 0) {
        fprintf(stderr, "could not open %s, %d\n", filename, fd);
        return -1;
    }

    rc = fstat(fd, &buf);
    if (rc < 0) {
        fprintf(stderr, "could not stat file, %d\n", fd);
        return -1;
    }

    assert (buf.st_size % (sizeof(int) + 256) == 0);

    fp = fdopen(fd, "r");
    if (!fp) {
        fprintf(stderr, "could not get file pointer\n");
        return -1;
    }

    while (count < buf.st_size) {
        int file_cnt;
        char* fname;
        fname = (char *) malloc(256);
	if (fname == NULL) {
	    fprintf (stderr, "Unable to malloc fname\n");
	    assert (0);
	}
        if (read_filename_mapping(fp, &file_cnt, fname)) {
            fprintf(stderr, "could not read filemapping, count is %lu\n", count);
            return -1;
        }
	fprintf(stdout, "%s %d\n", fname, file_cnt);
        count += (sizeof(int) + 256);
    }
    return 0;
}

void read_output(char* dataflow_filename, char* merge_filename) {
    int df_fd;
    int merge_fd;
    off_t df_bytes_read = 0;
    struct stat df_buf;
    int rc;

    df_fd = open(dataflow_filename, O_RDONLY);
    if (df_fd == -1) {
        fprintf(stderr, "Could not open %s\n", dataflow_filename);
        return;
    }

    rc = fstat(df_fd, &df_buf);
    if (rc == -1) {
        fprintf(stderr, "could not stat %s\n", dataflow_filename);
        return;
    }

    merge_fd = open(merge_filename, O_RDONLY);
    if (merge_fd == -1) {
        fprintf(stderr, "Could not open %s\n", merge_filename);
        return;
    }

    // Read the dataflow.results file
    while (df_bytes_read < df_buf.st_size) {
        int i;
        struct taint_creation_info tci;
        u_long addr;
        u_long bufsize;
        rc = read(df_fd, &tci, sizeof(struct taint_creation_info));
        if (rc == -1) {
            fprintf(stderr, "Could not read taint_creation_info\n");
            return;
        }
        if (rc != sizeof(struct taint_creation_info)) {
            fprintf(stderr, "Exppected to read taint_creation_info of size %u but got %d\n",
                    sizeof(struct taint_creation_info), rc);
            return;
        }
        df_bytes_read += rc;
        fprintf(stderr, "Output rg: %llu, pid %d, syscall %lu, offset %d\n",
                tci.rg_id, tci.record_pid, tci.syscall_cnt, tci.offset);

        // read the address
        rc = read(df_fd, &addr, sizeof(u_long));
        if (rc == -1) {
            fprintf(stderr, "Failed to read address from header\n");
            return;
        }
        df_bytes_read += rc;

        // read the buffer size
        rc = read(df_fd, &bufsize, sizeof(u_long));
        if (rc == -1) {
            fprintf(stderr, "Failed to read size from header\n");
            return;
        }
        df_bytes_read += rc;

        for (i = 0; i < bufsize; i++) {
            u_long tokval;
            u_long bufaddr;
            u_long val;

            // Read the dataflow.results file first
            rc = read(df_fd, &bufaddr, sizeof(u_long));
            if (rc == -1) {
                fprintf(stderr, "Failed to read bufaddr\n");
                return;
            }
            df_bytes_read += rc;
            rc = read(df_fd, &val, sizeof(u_long));
            if (rc == -1) {
                fprintf(stderr, "Failed to read val\n");
                return;
            }
            df_bytes_read += rc;

            do {
                rc = read(merge_fd, &tokval, sizeof(u_long));
                if (rc == -1) {
                }
                if (tokval) {
                    fprintf(stdout, "%lx", bufaddr);
                    fprintf(stdout, "\t%lu\t", val);
                    fprintf(stdout, "\tmergeout: %lu\n", tokval);
                } else {
                    break;
                }
            } while(1);
        }
    }
}

int main(int argc, char** argv) {
    char* group_dir, *pid;
    char tokens_filename[256];
    char filenames_filename[256];
    char dataflow_filename[256];
    char merge_filename[256];

    if (argc < 2) {
        fprintf(stderr, "ERROR needs group_dir and pid\n");
        return 1;
    }
    group_dir = argv[1];
    
    if(argc > 2) { 
 	    pid = argv[2];
	    snprintf(tokens_filename, 256, "%s/tokens.%s", group_dir,pid);
	    snprintf(filenames_filename, 256, "%s/filenames.%s", group_dir, pid);
	    snprintf(dataflow_filename, 256, "%s/dataflow.result.%s", group_dir, pid);
    }
    else {
	    snprintf(tokens_filename, 256, "%s/tokens", group_dir);
	    snprintf(filenames_filename, 256, "%s/filenames", group_dir);
	    snprintf(dataflow_filename, 256, "%s/dataflow.result", group_dir);
    }

    snprintf(tokens_filename, 256, "%s/tokens", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);
    snprintf(dataflow_filename, 256, "%s/dataflow.result", group_dir);
    snprintf(merge_filename, 256, "%s/mergeout", group_dir);

    fprintf(stdout, "OUTPUT\n");
    read_output(dataflow_filename, merge_filename);


    return 0;
}
