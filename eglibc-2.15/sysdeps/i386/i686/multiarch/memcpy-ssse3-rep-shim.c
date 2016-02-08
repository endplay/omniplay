#include <stdlib.h>
#include <ctype.h>

static void (*pthread_log_tick)(void) = NULL;

void* __memcpy_ssse3_rep_shim (void* src, const void* dest, size_t n)
{
    if (pthread_log_tick) pthread_log_tick();
    return __memcpy_ssse3_rep (src, dest, n);
}

void memcpy_setup(void (*__pthread_log_tick)(void))
{
    pthread_log_tick = __pthread_log_tick;
}
