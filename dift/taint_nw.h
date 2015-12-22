#ifndef __TAINT_NW__
#define __TAINT_NW__

#ifdef __cplusplus
extern "C" {
#endif

/* Note: define exactly 1 of these 4 */
//#define USE_NW
#define USE_SHMEM
//#define USE_FILE
//#define USE_NULL

#ifdef USE_SHMEM
#define MAX_MERGE_SIZE 0x80000000 /*   2 GB */
#define MAX_OUT_SIZE   0x40000000 /*   1 GB */
#define MAX_DUMP_SIZE  0x80000000 /*   2 GB - streamsing so large=OK */
#define MAX_TOKENS_SIZE 0x1000000 /*  16 MB */
#endif

#define TAINT_DATA_MERGE  1
#define TAINT_DATA_OUTPUT 2
#define TAINT_DATA_INPUT  3
#define TAINT_DATA_ADDR   4

struct taint_data_header {
    uint32_t type;
    uint32_t datasize;
};

#ifdef __cplusplus
}
#endif

#endif

