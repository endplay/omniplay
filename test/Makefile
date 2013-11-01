CFLAGS := -Wall -Werror -g 
LDFLAGS := -Wall -Werror -g 

all: libutil.a parseklog parseulog launcher resume hello pthread_test parseckpt

parseklog: parseklog.c
	gcc parseklog.c -o parseklog -Wall -Werror -g

parseulog: parseulog.c
	gcc parseulog.c -o parseulog -Wall -Werror -g

parseckpt: parseckpt.c
	gcc parseckpt.c -o parseckpt -Wall -Werror -g

launcher: launcher.c libutil.a
	gcc launcher.c -o launcher libutil.a -Wall -Werror --static -g -I../../eglibc-2.15/prefix/include -L../../eglibc-2.15/prefix/lib

resume: resume.o libutil.a
	gcc resume.c -o resume libutil.a -Wall -Werror --static -g

hello: hello.c
	gcc hello.c -o hello -I../../eglibc-2.15/prefix/include -L../../eglibc-2.15/prefix/lib 

pthread_test.o: pthread_test.cc
	c++ pthread_test.cc -o pthread_test.o -c 

pthread_test: pthread_test.o
	c++ pthread_test.o -o pthread_test -L../eglibc-2.15/prefix/lib -pthread

libutil.a: util.o
	ar rv libutil.a util.o
	ranlib libutil.a

clean:
	rm *.a *.o
