CC=gcc

all: taints_index_test

taints_test: taints_test.c taints.h
	$(CC) -o taints_test taints_test.c taints.o -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -lglib-2.0

taints_index_test: taints_index_test.c taints_index.h taints_graph.h
	$(CC) -g -o taints_index_test taints_index_test.c -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -lglib-2.0

taints_merge_test: taints_merge_test.c taints_graph.h
	$(CC) -g -o taints_merge_test taints_merge_test.c -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -lglib-2.0

taints_merge_list_test: taints_merge_list_test.c taints_merge_list.h
	$(CC) -g -o taints_merge_list_test taints_merge_list_test.c -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -lglib-2.0

taints: taints.c taints.h
	$(CC) -o taints.o -c taints.c -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include

taints_glib_hash: taints_glib_hash.c taints.h
	$(CC) -DTAINTS_HASH -o taints_glib_hash.o -c taints_glib_hash.c -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include

taints_glib_hash_test: taints_glib_hash taints_glib_hash.c taints.h taints_test.c
	$(CC) -o taints_glib_hash_test taints_test.c taints_glib_hash.o -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -lglib-2.0

slab_alloc_test: slab_alloc_test.c
	$(CC) -g -o slab_alloc_test slab_alloc_test.c

clean:
	rm *.o taints_test
