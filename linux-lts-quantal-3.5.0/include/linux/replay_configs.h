#ifndef __REPLAY_CONFIG_H
#define __REPLAY_CONFIG_H

/*
 * Enables read compression, sourcing reads of a file from another uncompressed file.
 * This will have potential data size and performance implications on both recorded/replayed files
 * AND non-record/replay reads from files whose creations were recorded.
 *
 * It may (however) drastically reduce the size of recorded reads by recording the origin of data, instead of its contents.
 *
 * This automatically disables TRACE_*
 */
//#define REPLAY_COMPRESS_READS

/* 
 * Double checks to make sure the data that comes out of a REPLAY_COMPRESS_READS
 * file is the expected data...
 */
//#define VERIFY_COMPRESSED_DATA

/* 
 * Enables replay-graph tracking for file, pipe, and socket IO respectively.
 */
#define TRACE_READ_WRITE
#define TRACE_PIPE_READ_WRITE
#define TRACE_SOCKET_READ_WRITE

#endif
