// A simple program to reset the replay ndx

#include "util.h"

int main(int argc, char** argv)
{
    int fd;
    devspec_init(&fd);
    reset_replay_ndx(fd);
    return 0;
}
