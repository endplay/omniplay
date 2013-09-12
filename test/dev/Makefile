obj-m := spec.o

spec-y := devspec.o

KERNEL_DIR := /lib/modules/3.5.7.13/build

all:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(shell pwd) modules

clean:
	$(RM) *.o *.a .depend *.d *.ko *.mod.c

install:
	install spec.ko /lib/modules/3.5.7.13/kernel/fs/
	/sbin/depmod
