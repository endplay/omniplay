#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <errno.h>
#include <unordered_set>
#include <vector>


using namespace std;

typedef unordered_set<u_int> my_set;





int main(int argc, char* argv[]) {
    char instructionsfile[256];    
    int rc;
    FILE* file;
    u_int curr_inst;
    my_set cinsts;
    vector<u_int> list;

    int syscall_count = 0;
    int event_count = 0;

    sprintf (instructionsfile, "%s", argv[1]);
    file = fopen(instructionsfile, "r");

    if (file == NULL) { 
	cout << "couldn't open" << instructionsfile << " " << errno << endl;
	return -1;
    }

    //while we aren't finished with the file yet
    while(!feof(file)) { 
	do { 
	    rc = fread((void *)&curr_inst, sizeof(u_int), 1, file);
	    if (curr_inst != 0 && event_count != 0) { 
		cinsts.insert(curr_inst);
		list.push_back(curr_inst);
	    }
	    if (event_count == 0) {
		event_count = curr_inst;
	    }

	}while( rc > 0 && curr_inst != 0);

	if(rc != 0)
	    syscall_count++;

	printf("%d %d %d\n",event_count,cinsts.size(), list.size());
	
	
	event_count = 0;
	list.clear();
	cinsts.clear();

    }

//    printf("%d syscalls\n",syscall_count);
    return 0;
}
