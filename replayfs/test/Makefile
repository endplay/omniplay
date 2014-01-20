
TARGETS=test_version write_twice test_dirops test_unlink vls vcd test_read_write

all: $(TARGETS)

test_version: test_version.c ../replayfs_fs.h
	gcc test_version.c -g3 -I.. -o test_version

write_twice:  write_twice.c
	gcc write_twice.c -g3 -I.. -o write_twice

test_dirops: test_dirops.c
	gcc $^ -g3 -I.. -o $@

test_unlink: test_unlink.c
	gcc $^ -g3 -I.. -o $@

test_read_write: test_read_write.c
	gcc $^ -g3 -I.. -o $@

vls: vls.c
	gcc $^ -g3 -I.. -o $@

vcd: vcd.c
	gcc $^ -g3 -I.. -o $@

clean:
	rm -f *.o $(TARGETS)


