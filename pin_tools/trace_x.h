#ifndef TRACE_X_H
#define TRACE_X_H

#include <stdint.h>

struct x_byte_result {
    int x;              // x-coord of the X screen
    int y;              // y-coord of the X screen
    uint64_t rg_id;
    int record_pid;
    int syscall_cnt;
    unsigned int token_num; // taint
};

#endif // TRACE_X_H
