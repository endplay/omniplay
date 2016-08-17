CC := gcc

CFLAGS := -Wall -Werror -g
LDFLAGS := -Wall -Werror -g 

DEPS_DIR := .deps

TARGETS=get_partition_data get_timing_data

# For automatic .h dependency tracking... may not work perfectly for launcher as
#    the include path changes for it
CFILES=$(wildcard *.c)
DEPS=$(patsubst %.c, .deps/%.d, $(CFILES))

.PHONY: all
all: $(TARGETS)

# Build dependencies + any extra flags

get_partition_data: get_partition_data.cpp ../mkpartition_utils.o
	c++ -std=c++0x ../mkpartition_utils.o ../libutil.a get_partition_data.cpp -o get_partition_data -Wall -Werror -O8


get_timing_data: get_timing_data.cpp ../mkpartition_utils.o
	c++ -std=c++0x ../mkpartition_utils.o ../libutil.a get_timing_data.cpp -o get_timing_data -Wall -Werror -O8


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

