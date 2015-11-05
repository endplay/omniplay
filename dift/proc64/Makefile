all: out2mergecmp stream streamserver # streamctl mkmerge merge3

mkmerge: mkmerge.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o mkmerge mkmerge.cpp ../maputil.c -lrt

stream: stream.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o stream stream.cpp ../maputil.c -lrt -lpthread

merge3: merge3.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o merge3 merge3.cpp ../maputil.c -lrt -lpthread

out2mergecmp: out2mergecmp.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o out2mergecmp out2mergecmp.cpp ../maputil.c 

streamserver: streamserver.cpp streamnw.cpp streamnw.h ../../test/streamserver.h ../../test/util.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o streamserver streamserver.cpp streamnw.cpp ../../test/libutil.a -lrt -lpthread

streamctl: streamctl.cpp streamnw.cpp streamnw.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o streamctl streamctl.cpp streamnw.cpp 
