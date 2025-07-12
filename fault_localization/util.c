#include "util.h"

__thread FLStat stat_buffer[FL_STAT_BUFFER_FULL];
__thread short stat_buffer_top = FL_STAT_BUFFER_EMPTY;
__thread unsigned long long int current_pid = 0;

unsigned long long int my_getpid()
{
    if (current_pid == 0)
    {
        current_pid = (unsigned long long int)getpid();
    }
    return current_pid;
}