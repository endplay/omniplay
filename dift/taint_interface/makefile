all: test_taint_interface test_taint_forward_interface

test_taint_interface.o: test_taint_interface.c
	clang -o test_taint_interface.o -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -c test_taint_interface.c

test_taint_interface: test_taint_interface.o
	clang -o test_taint_interface test_taint_interface.o ../taints/obj/taint_full_interface.o ../obj-ia32/xray_slab_alloc.o -lglib-2.0

test_taint_forward_interface.o: test_taint_forward_interface.c
	clang -o test_taint_forward_interface.o -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -c test_taint_forward_interface.c

test_taint_forward_interface: test_taint_forward_interface.o
	clang -o test_taint_forward_interface test_taint_forward_interface.o ../taints/obj/taint_forward_interface.o ../obj-ia32/xray_slab_alloc.o -lglib-2.0

clean:
	rm *.o test_taint_interface
