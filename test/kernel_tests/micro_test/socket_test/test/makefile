
TARGETS=socket_server socket_client socket_rdwr_server socket_rdwr_client

all: $(TARGETS)

socket_server: server.c
	gcc -g3 -O2 -o $@ $<

socket_client: client.c
	gcc -g3 -O2 -o $@ $<

socket_rdwr_server: server.c
	gcc -g3 -O2 -DUSE_RDWR -o $@ $<

socket_rdwr_client: client.c
	gcc -g3 -O2 -DUSE_RDWR -o $@ $<

clean:
	rm -f $(TARGETS)
