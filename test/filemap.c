#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "util.h"

struct replayfs_syscache_id {
	loff_t unique_id : 48; 
	loff_t pid : 16; 
	loff_t sysnum : 56; 
	loff_t mod : 8;
} __attribute__((aligned(16)));

struct replayfs_btree_value {
	struct replayfs_syscache_id id;

	size_t buff_offs;
};

struct replay_filemap_entry {
	struct replayfs_btree_value bval;
	loff_t offset;
	size_t size;
	size_t read_offset;
};

// format: ./filemap <filename> <output>
int main(int argc, char** argv)
{
    int fd_file;
    int fd_spec;
    int rc;
    int num_entries, i;
    FILE* fp;
    struct stat buf;
    struct replay_filemap_entry* entries;

    if (argc < 3) {
        fprintf(stderr, "Not enough args, usage: ./filemap <filename> <output>\n");
        return 0;
    }

    fd_spec = open ("/dev/spec0", O_RDWR);
    if (fd_spec < 0) {
        perror ("open /dev/spec0");
        return -1;
    }

    // open the file we want the mapping of
    fd_file = open(argv[1], O_RDONLY);
    if (fd_file < 0) {
        fprintf(stderr, "Could not open file %s\n", argv[1]);
        return 0;
    }
    rc = fstat(fd_file, &buf);
    if (rc) {
        fprintf(stderr, "could not fstat\n");
        return 0;
    }
    num_entries = get_num_filemap_entries(fd_spec, fd_file, 0, buf.st_size);
    if (num_entries < 0) {
        fprintf(stderr, "could not get number of entries\n");
        return 0;
    }
    fprintf(stderr, "Got %d entries\n", num_entries);

    if (num_entries == 0) {
        return 0;
    }

    entries = (struct replay_filemap_entry *) malloc(sizeof(struct replay_filemap_entry) * num_entries);
    rc = get_filemap(fd_spec, fd_file, 0, buf.st_size, entries, num_entries);

    if (rc) {
        fprintf(stderr, "could not get filemap\n");
        return -1;
    }
    
    fp = fopen(argv[2], "w");
    for (i=0; i < num_entries; i++) {
        struct replay_filemap_entry* entry;
        entry = entries + i;
	fprintf(fp, "%lld %d %lld %d %lld %d\n",
			entry->offset,
			entry->size,
			(loff_t)entry->bval.id.unique_id,
			entry->bval.id.pid,
			(loff_t)entry->bval.id.sysnum,
			entry->read_offset);
    }

    fflush(fp);
    fclose(fp);

    free(entries);
    return 0;
}
