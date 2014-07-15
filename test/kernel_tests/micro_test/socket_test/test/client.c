#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


//char *socket_path = "./socket";
char *socket_path = "\0hidden";

int main(int argc, char *argv[]) {
	struct sockaddr_un addr;
	char buf[100];
	int fd,rc;

	if (argc > 1) socket_path=argv[1];

	if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("connect error");
		exit(-1);
	}

	while( (rc=read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		struct iovec iov;
		iov.iov_base = buf;
		iov.iov_len = rc;
		if (writev(fd, &iov, 1) != rc) {
			if (rc > 0) fprintf(stderr,"partial write");
			else {
				perror("writev error");
				exit(-1);
			}
		}
	}

	return 0;
}
