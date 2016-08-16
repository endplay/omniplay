TARGETS=out2mergecmp streamserver stream recv_replay_files pound_cpu
LBITS:= $(shell getconf LONG_BIT)
ifeq ($(LBITS),64)
	LIBUTIL:=
	LIBH:=
	SSFLAGS := -DBUILD_64
else
	LIBUTIL:= ../../test/libutil.a
	LIBH:= ../../test/util.h
	SSFLAGS := -DBUILD_32
endif


all: $(TARGETS)
mkmerge: mkmerge.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o mkmerge mkmerge.cpp ../maputil.c -lrt

stream: stream.cpp streamnw.cpp streamnw.h ../maputil.c ../maputil.h ../taint_nw.h ../../test/streamserver.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o stream stream.cpp streamnw.cpp ../maputil.c -lrt -lpthread 

recv_replay_files: recv_replay_files.cpp streamnw.cpp streamnw.h  ../../test/streamserver.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o recv_replay_files recv_replay_files.cpp streamnw.cpp -lrt -lpthread

merge3: merge3.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o merge3 merge3.cpp ../maputil.c -lrt -lpthread

out2mergecmp: out2mergecmp.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o out2mergecmp out2mergecmp.cpp ../maputil.c 

streamserver: streamserver.cpp streamnw.cpp streamnw.h ../../test/streamserver.h $(LIBH)
	$(CXX) -std=c++0x $(SSFLAGS) -Wall -Werror -O8 -o streamserver streamserver.cpp streamnw.cpp $(LIBUTIL) -lrt -lpthread

streamctl: streamctl.cpp streamnw.cpp streamnw.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o streamctl streamctl.cpp streamnw.cpp 

clean:
	rm -f *.a *.o $(TARGETS)
