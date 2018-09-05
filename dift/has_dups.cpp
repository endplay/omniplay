#include <stdio.h>
#include <stdlib.h>
#include "maputil.h"

#include <unordered_map>
#include <unordered_set>

using namespace std;

int main (int argc, char* argv[]) 
{
    long rc;
    int mfd;
    u_long mdatasize, mmapsize, addr;
    u_long* mbuf, *morig;
    std::unordered_map<u_long,u_long *> maps;
    u_long total_addr = 0, total_count = 0, total_nondups = 0;

    // First stage - read in addr map
    rc = map_file (argv[1], &mfd, &mdatasize, &mmapsize, (char **) &mbuf);
    if (rc < 0) return rc;

    morig = mbuf;
    mbuf++;
    mbuf++;
    while ((u_long) mbuf < (u_long) morig + mdatasize) {
	addr = *mbuf;
	mbuf++;

	// Should not be dups but check anyway
	if (maps.count(addr)) {
	    printf ("addr %lx already in map\n", addr);
	}
	maps[addr] = mbuf;
	
	int count = 0;
	std::unordered_set<u_long> values;
	
	while (*mbuf) {
	    values.insert(*mbuf);
	    count++;
	    mbuf++;
	}
	mbuf++;
	total_addr++;
	total_count += count;
	total_nondups += values.size();
    }

    printf ("%lu addresses, %lu values, %lu non-dups\n", total_addr, total_count, total_nondups);

    return 0;
}
