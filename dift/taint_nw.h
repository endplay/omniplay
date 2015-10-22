#ifndef __TAINT_NW__
#define __TAINT_NW__

#define USE_NW

#ifdef __cplusplus
extern "C" {
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

