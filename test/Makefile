CC := gcc

CFLAGS := -Wall -Werror -g 

#LDLIBS := libutil.a

KERN_CONFIG := replay_headers/include/linux/replay_configs.h

DEPS_DIR := .deps

TARGETS=libutil.a parseklog parseulog parsemlog launcher resume parseckpt \
	getstats filemap replay_pause parseklog_new 

.PHONY: all
all: $(TARGETS)

# Build dependencies + any extra flags
launcher: libutil.a
launcher: CFLAGS += --static -I../../eglibc-2.15/prefix/include -L../../eglibc-2.15/prefix/lib 

resume: libutil.a
resume: CFLAGS += --static

getstats: libutil.a
getstats: CFLAGS += --static

filemap: libutil.a 
filemap: CFLAGS += --static

replay_pause: CFLAGS += --static

find_record_time: CFLAGS += --static

parseklog: $(KERNEL_COFNIG)

parseklog_new: parseklib.o
parseklog_pipe: parseklib.o
parseklog_graph: parseklib.o

rewriteklog: parseklib.o

libutil.a: util.o
	ar rv $@ $<
	ranlib $@

parseklib.o: $(KENREL_CONFIG)

.PHONY: clean
clean:
	rm -f *.a *.o $(TARGETS)


