#include <unistd.h>
#include <execinfo.h>
#include "control.h"

#ifdef __cplusplus
extern "C" {
#endif

void FL_stat();

void FL_stat()
{
    // __builtin_return_address
    // backtrace()
    FLStat stat;
    if (unlikely(FL_state == FL_RECORD))
    {
        stat.pid = my_getpid();
        void *backtrace_buffer[2];
        backtrace(backtrace_buffer, 2);
        stat.loc = (unsigned long long int)backtrace_buffer[1];
        // // see: https://gcc.gnu.org/onlinedocs/gcc/Return-Address.html
        // stat.loc = __builtin_extract_return_addr(__builtin_return_address (0));
        // printf("FL_stat: pid = %llu, loc = %llu bt = %p\n", stat.pid, stat.loc, backtrace_buffer[1]);
        stat_buffer[stat_buffer_top] = stat;
        // FL_send_stat_data(stat_buffer, 1);
        // FL_send_stat_data(&stat, 1);
        stat_buffer_top += 1;
        if (stat_buffer_top == FL_STAT_BUFFER_FULL)
        {
            // send all data in buffer
            FL_send_stat_data(stat_buffer, stat_buffer_top);
            stat_buffer_top = FL_STAT_BUFFER_EMPTY;
        }
    }
}

#ifdef __cplusplus
}
#endif