CFLAGS := -Wall -Werror -g 
LDFLAGS := -Wall -Werror -g 

all: libutil.a parseklog parseulog launcher resume

parseklog: parseklog.c
	gcc parseklog.c -o parseklog -Wall -Werror -g

parseulog: parseulog.c
	gcc parseulog.c -o parseulog -Wall -Werror -g

parseckpt: parseckpt.c
	gcc parseckpt.c -o parseckpt -Wall -Werror -g

launcher: launcher.c libutil.a
	gcc launcher.c -o launcher libutil.a -Wall -Werror --static -g

resume: resume.o libutil.a
	gcc resume.c -o resume libutil.a -Wall -Werror --static -g

libutil.a: util.o
	ar rv libutil.a util.o
	ranlib libutil.a

clean:
	rm *.a *.o
