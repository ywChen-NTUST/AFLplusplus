#define _XOPEN_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include "control.h"

__attribute__((constructor(FL_PRIO))) void FL_initial();
__attribute__((destructor(FL_PRIO))) void FL_finish();
void FL_crash_handler(int signum);

static void (*afl_sig_handler)(int);

// this will only executed once in a fuzz testing
void FL_initial()
{
    int res;
    res = FL_create_command_socket();
    if (res == -1)
    {
        puts("Failed to create command socket");
        return;
    }

    struct sigaction FL_crash_sa;
    FL_crash_sa.sa_handler = FL_crash_handler;
    struct sigaction maybe_afl_sa;
    sigaction(SIGSEGV, NULL, &maybe_afl_sa);
    afl_sig_handler = maybe_afl_sa.sa_handler;
    sigaction(SIGSEGV, &FL_crash_sa, NULL);
    sigaction(SIGBUS, &FL_crash_sa, NULL);
    sigaction(SIGILL, &FL_crash_sa, NULL);

    // check if we are running under AFL++
    if (getenv("__AFL_SHM_ID") && FL_state == FL_DISABLE)
    {
        FL_state = FL_RECORD;
        // puts("FL_ENABLE");
        FL_connect_data_socket();
    }

    pthread_t command_thread;
    pthread_create(&command_thread, NULL, FL_commmand_handler, NULL);
}

void FL_finish()
{
    FLStat stat;
    if (unlikely(FL_state == FL_RECORD))
    {
        if (stat_buffer_top != FL_STAT_BUFFER_EMPTY)
        {
            // send all data in buffer
            FL_send_stat_data(stat_buffer, stat_buffer_top);
            stat_buffer_top = FL_STAT_BUFFER_EMPTY;
        }
        stat.pid = my_getpid();
        stat.loc = FL_NORMAL | ((unsigned long long int)1<<63);
        FL_send_stat_data(&stat, 1);
    }
}

void FL_crash_handler(int signum)
{
    // expose singal outside
    struct sigaction default_sa;
    default_sa.sa_handler = SIG_DFL;
    sigaction(signum, &default_sa, NULL);
    FLStat stat;

    if (unlikely(FL_state == FL_RECORD))
    {
        if (stat_buffer_top != FL_STAT_BUFFER_EMPTY)
        {
            // send all data in buffer
            FL_send_stat_data(stat_buffer, stat_buffer_top);
            stat_buffer_top = FL_STAT_BUFFER_EMPTY;
        }
        stat.pid = my_getpid();
        stat.loc = FL_CRASH | ((unsigned long long int)1<<63);
        FL_send_stat_data(&stat, 1);
    }

    afl_sig_handler(signum);
}