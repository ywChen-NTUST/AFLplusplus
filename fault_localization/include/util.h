#ifndef _FL_UTIL_H_
#define _FL_UTIL_H_

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define FL_PRIO 101
#define FL_DATA_SOCKET "/tmp/FL_data.sock"

typedef enum {
    FL_DISABLE = 0,
    FL_RECORD,
} FLState;

typedef enum {
    FL_NORMAL = 0,
    FL_CRASH = 1,
    FL_ERROR = 2,
} FLStatus;

typedef struct {
    unsigned long long int pid;
    unsigned long long int loc;
} FLStat;

extern __thread unsigned long long int current_pid;
unsigned long long int my_getpid();

#define FL_STAT_BUFFER_EMPTY 0
#define FL_STAT_BUFFER_FULL 64
extern __thread FLStat stat_buffer[FL_STAT_BUFFER_FULL];
extern __thread short stat_buffer_top;

#endif