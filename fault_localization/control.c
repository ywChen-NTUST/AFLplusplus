#include <linux/limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "control.h"
#include "util.h"

FLState FL_state = FL_DISABLE;
static int command_fd;
static int data_fd;

int create_unix_socket(char *name)
{
    int fd;
    struct sockaddr_un serv_addr;

    if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
        return -1;

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_LOCAL;
    strcpy(serv_addr.sun_path, name);

    if(bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        return -1;

    if(listen(fd, 1) == -1)
        return -1;

    return fd;
}

int FL_create_command_socket()
{
    char socket_name[PATH_MAX];
    sprintf(socket_name, "/tmp/FL_command_%d.sock", getpid());

    command_fd = create_unix_socket(socket_name);
    if(command_fd == -1)
    {
        perror("FL_create_command_socket");
        return -1;
    }
    return command_fd;
}

void *FL_commmand_handler(void *arg)
{
    int comm_fd;
    int command;
    struct sockaddr_un client_addr;

    socklen_t socklen = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    while(1){
        if((comm_fd =
                accept(command_fd, (struct sockaddr_un*)&client_addr, &socklen)
            ) == -1)
        {
            perror("FL_commmand_handler");
            _exit(1);
        }

        if(read(comm_fd, &command, 4) == 4)
        {
            printf("FL command: %d\n", command);
            switch(command){
                case FL_DISABLE:
                    FL_state = FL_DISABLE;
                    puts("FL_DISABLE");
                    close(data_fd);
                    break;
                case FL_RECORD:
                    FL_state = FL_RECORD;
                    puts("FL_ENABLE");
                    FL_connect_data_socket();
                    break;
                default:
                    break;
            }
        }
        close(comm_fd);
    }
}

int FL_connect_data_socket()
{
    struct sockaddr_un serv_addr;

    if ((data_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
    {
        puts("FL_send_stat_data socket");
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_LOCAL;
    strcpy(serv_addr.sun_path, FL_DATA_SOCKET);

    if(connect(data_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        puts("FL_send_stat_data connect");
        return -1;
    }
    return 0;
}

void FL_send_stat_data(FLStat *stat, int count)
{
    write(data_fd, stat, sizeof(FLStat) * count);
}