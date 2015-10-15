all: mkmerge merge3 out2mergecmp fullrecv stream streamserver streamctl

mkmerge: mkmerge.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o mkmerge mkmerge.cpp ../maputil.c -lrt

stream: stream.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o stream stream.cpp ../maputil.c -lrt -lpthread

merge3: merge3.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o merge3 merge3.cpp ../maputil.c -lrt -lpthread

out2mergecmp: out2mergecmp.cpp ../maputil.c ../maputil.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o out2mergecmp out2mergecmp.cpp ../maputil.c 

fullrecv: fullrecv.c
	$(CXX) -std=c++0x -Wall -Werror -O8 -o fullrecv fullrecv.c

streamserver: streamserver.cpp streamnw.cpp streamnw.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o streamserver streamserver.cpp streamnw.cpp -lrt -lpthread

streamctl: streamctl.cpp streamnw.cpp streamnw.h
	$(CXX) -std=c++0x -Wall -Werror -O8 -o streamctl streamctl.cpp streamnw.cpp 
