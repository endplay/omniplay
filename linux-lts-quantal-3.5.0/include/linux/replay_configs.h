#ifndef __REPLAY_CONFIG_H
#define __REPLAY_CONFIG_H

/*
 * Includes information in the log allowing all writes to be totally ordered.
 * Intended use is versioned FS applicaiton
 */
#define ORDER_WRITES

/* 
 * Enables replay-graph tracking for file, pipe, and socket IO respectively.
 */
#define TRACE_READ_WRITE
#define TRACE_PIPE_READ_WRITE
#define TRACE_SOCKET_READ_WRITE

#endif
