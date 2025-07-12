#ifndef _FL_CONTROL_H_
#define _FL_CONTROL_H_

#include "util.h"

extern FLState FL_state;

int FL_create_command_socket();
void *FL_commmand_handler(void *arg);
int FL_connect_data_socket();
void FL_send_stat_data(FLStat *stat, int count);

#endif