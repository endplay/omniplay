CC := gcc

CFLAGS := -Wall -Werror -g
LDFLAGS := -Wall -Werror -g 

#LDLIBS := libutil.a

KERN_CONFIG := replay_headers/include/linux/replay_configs.h

DEPS_DIR := .deps

TARGETS=parseklog parseulog parsemlog launcher resume parseckpt \
	getstats filemap replay_pause reset_ndx currentpid seqtt partt fulltt fullsend mkpartition streamtt streamctl sync_files

# For automatic .h dependency tracking... may not work perfectly for launcher as
#    the include path changes for it
CFILES=$(wildcard *.c)
DEPS=$(patsubst %.c, .deps/%.d, $(CFILES))

.PHONY: all
all: $(TARGETS)

# Build dependencies + any extra flags

launcher: libutil.a
launcher: CFLAGS += --static -I../../eglibc-2.15/prefix/include -L../../eglibc-2.15/prefix/lib 

resume: libutil.a
resume: CFLAGS += --static

getstats: libutil.a

filemap: libutil.a 

parseklog: parseklib.o

rewriteklog: parseklib.o

libutil.a: util.o parseklib.o
	ar rv $@ $^
	ranlib $@

parseklib.o: $(KENREL_CONFIG)

reset_ndx: libutil.a

currentpid: libutil.a

seqtt: libutil.a 
seqtt: LDLIBS += -lrt 

partt: libutil.a
partt: LDFLAGS += -pthread

streamtt: libutil.a streamtt.cpp 
	c++ -std=c++0x streamtt.cpp libutil.a -pthread -lrt -o streamtt -Wall -Werror

streamctl: streamctl.cpp streamserver.h parseklib.o streamnw.cpp streamnw.h
	c++ -Wall -Werror -std=c++0x streamctl.cpp streamnw.cpp parseklib.o -o streamctl -g

fulltt: libutil.a

fullsend: libutil.a

mkpartition: libutil.a mkpartition.cpp 
	c++ -Wall -Werror -std=c++0x mkpartition.cpp libutil.a -pthread -lrt -o mkpartition -g

sync_files: sync_files.cpp streamserver.h parseklib.o streamnw.cpp streamnw.h
	c++ -Wall -Werror -std=c++0x sync_files.cpp parseklib.o streamnw.cpp -o sync_files 

.PHONY: clean
clean:
	rm -f *.a *.o $(TARGETS)

.deps/%.d: %.c .dep_dirs_made
	@$(CC) $(CFLAGS) -M -o $@ $<

.dep_dirs_made:
	@touch .dep_dirs_made
	@mkdir .deps

-include $(DEPS)

.PHONY: nuke
nuke: clean
	rm -rf .deps .dep_dirs_made

