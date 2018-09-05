CC := gcc

CFLAGS :=  -g
LDFLAGS := -Wall -Werror -g 

#LDLIBS := libutil.a


TARGETS=generate_splits get_partition_data get_ulevel_splits


.PHONY: all
all: $(TARGETS)


generate_splits_utils.o: generate_splits_utils.h generate_splits_utils.cpp
	c++ -std=c++0x -Og generate_splits_utils.cpp -c -o generate_splits_utils.o -g
generate_splits: generate_splits.cpp generate_splits_utils.h generate_splits_utils.o
	c++ -std=c++0x -Og  generate_splits_utils.o generate_splits.cpp -o generate_splits  -g

get_partition_data: get_partition_data.cpp generate_splits_utils.h generate_splits_utils.o
	c++ -std=c++0x generate_splits_utils.o get_partition_data.cpp -o get_partition_data -g

get_ulevel_splits: get_ulevel_splits.cpp generate_splits_utils.h generate_splits_utils.o
	c++ -std=c++0x generate_splits_utils.o get_ulevel_splits.cpp -o get_ulevel_splits


.PHONY: clean
clean:
	rm -f *.a *.o $(TARGETS)
