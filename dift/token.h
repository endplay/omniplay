#ifndef TOKEN_H
#define TOKEN_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FILENO_STDIN        0
#define FILENO_STDOUT       1
#define FILENO_STDERR       2
#define FILENO_NAME         3
#define FILENO_ARGS         4
#define FILENO_ENVP         5
#define FILENO_SELECT       6

/* starting fileno number, after constants */
#define FILENO_START        7

/* Token types, i.e. the source of the token */
#define TOK_READ 1
#define TOK_WRITE 2
#define TOK_EXEC 3
#define TOK_WRITEV 4
#define TOK_RECV 5
#define TOK_SENDMSG 6
#define TOK_RECVMSG 7
#define TOK_PREAD 8
/* Select on a file descriptor */
#define TOK_SELECT 9


/* A token represents one or more contiguous inputs,
 * e.g. a range of bytes from read
 *  	or a configuration token (in ConfAid's case) */
struct token {
    int16_t type;                  // See types above, the source of the input
    int16_t record_pid;            // record thread/process
    uint32_t token_num;   // Unique identifier for start of range
    uint32_t size;        // Size of range (1 for single input)
    int32_t syscall_cnt;
    int32_t byte_offset;
#ifdef CONFAID
    char config_token[256];    // Name of the config token
    int32_t line_num;              // Line number
    char config_filename[256]; // Name of the config file
#else
    int32_t fileno;                // a mapping to the corresponding file/socket that this token came from
#endif
    uint64_t rg_id;            // replay group
};

#ifdef __cplusplus
}
#endif

#endif // XRAY_TOKEN_H
