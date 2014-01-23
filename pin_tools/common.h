#ifndef COMMON_H
#define COMMON_H

//#define CALLBACK_PRINT fprintf
#define CALLBACK_PRINT(x,...);

#define ERROR_PRINT fprintf
//#define ERROR_PRINT(x,...); 

/*
#define STATIC_PRINT(args...) \
{                           \
    fprintf(LOG_F, args);   \
    fflush(LOG_F);          \
}
*/
#define STATIC_PRINT(x,...); 

//#define MYASSERT(x) assert(x)
#define MYASSERT(x);

//#define INFO_PRINT fprintf
#define INFO_PRINT(x,...);

//#define PRINT_SPEC_VECTOR if(spec_on) print_dependency_vector
//#define PRINT_SPEC_VECTOR print_dependency_vector
#define PRINT_SPEC_VECTOR(x,...);

//#define SPEC_PRINT if(spec_on) fprintf
//#define SPEC_PRINT fprintf
#define SPEC_PRINT(x,...);

//#define PRINT_INST_VECTOR print_dependency_vector
#define PRINT_INST_VECTOR(x,...);

//#define PRINT_ANALYSIS_VECTOR print_dependency_vector
#define PRINT_ANALYSIS_VECTOR(x,...);
//#define ANALYSIS_PRINT fprintf
#define ANALYSIS_PRINT(x,...); 

//#define PRINT_DEP_VECTOR print_dependency_vector
#define PRINT_DEP_VECTOR(x,...);
//#define DEP_PRINT fprintf
#define DEP_PRINT(x,...); 

//#define PRINT_DEP1_VECTOR print_dependency_vector
#define PRINT_DEP1_VECTOR(x,...);
//#define DEP1_PRINT fprintf
#define DEP1_PRINT(x,...); 

#define LARGEFILE_USED
//#define SIGNAL_PRINT fflush(log_f); fprintf
#define SIGNAL_PRINT(x,...);

// #define INTER_PROCESS_PROPAGATION

//rollback codes
#define SUCCESS 0
#define LIMIT 1
#define FAIL 2

#define SET 0
#define MERGE 1

#define NO_ANALYSIS 0
#define REQUEST_ANALYSIS 1
#define TIME_ANALYSIS 2
#define DIFF_ANALYSIS 3
#define MULTI_ANALYSIS 4

#define NO_METRIC 0
#define LATENCY_METRIC 1
#define CPU_METRIC 2
#define DISK_METRIC 3

#define CLOEXEC 1

#define NUM_REGS 128
#define FIRST_TABLE_SIZE 131072
#define SECOND_TABLE_SIZE 1024
#define THIRD_TABLE_SIZE 32

#define FIRST_TABLE_BITS 17
#define SECOND_TABLE_BITS 10
#define THIRD_TABLE_BITS 5

#define MID_INDEX_MASK 0x000003FF
#define LOW_INDEX_MASK 0x0000001F
#define DIRECT_MASK 0x00000001
//#define VECTOR_SIZE 96 //1024 bits - 128 bytes
//#define VECTOR_SIZE 64 //1024 bits - 128 bytes
//#define VECTOR_SIZE_INT VECTOR_SIZE/32

#define REG_READ  0x01
#define REG_WRITE 0x02

/*Important EFLAGS for CMOV */
#define CF_MASK 0x01
#define PF_MASK 0x04
#define ZF_MASK 0x40
#define SF_MASK 0x80
#define OF_MASK 0x800
#define AF_MASK 0x10
#define DF_MASK 0x400

#define AF_FLAG 0
#define CF_FLAG 1
#define PF_FLAG 2
#define ZF_FLAG 3
#define SF_FLAG 4
#define OF_FLAG 5

#define NUM_FLAGS 6

#define CMOV_GENERIC 1
#define CMOVBE       2
#define CMOVL        3
#define CMOVNL       4
#define CMOVLE       5
#define CMOVNLE      6

#define MAX_SPEC_INSTS 80
#define MAX_HASH_LOG 50
#define MAX_CKPTS 5
#define TOTAL_MAX_CKPTS 10
#define MAX_SPEC_MEM_MODS 10000

#define MAX_NUM_BBLOCKS 2000

#define GET_TIME(x) __asm__ volatile(".byte 0x0f,0x31":"=A"(x))
#define SPECIAL_REG(X) (X == LEVEL_BASE::REG_EBP || X == LEVEL_BASE::REG_ESP)
#endif
