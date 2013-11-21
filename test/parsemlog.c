#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

struct reserved_mapping {
	unsigned long m_begin;
	unsigned long m_end;
};

int main(int argc, char* argv[])
{
	int fd, rc;
	int size;
	int i = 0;
	int num_entries = 0;
	struct stat st;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror ("open");
		return fd;
	}

	rc = fstat(fd, &st);
	if (rc < 0) {
		perror ("stat");
		return rc;
	}
	size = st.st_size;

	num_entries = size / sizeof(struct reserved_mapping);

	for (i = 0; i < num_entries; i++) {
		struct reserved_mapping rm;
		rc = read(fd, &rm, sizeof(struct reserved_mapping));
		if (rc != sizeof(struct reserved_mapping)) {
			perror ("read");
			return rc;
		}
		printf("[%lx, %lx) len: %ld\n", rm.m_begin, rm.m_end, rm.m_end - rm.m_begin);
	}

	return 0;
}
