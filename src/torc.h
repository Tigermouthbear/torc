#ifndef TORC_TORC_H
#define TORC_TORC_H

#include <stdbool.h>
#include <pthread.h>

#define TORC_SETCONF "SETCONF"
#define TORC_RESETCONF "RESETCONF"
#define TORC_GETCONF "GETCONF"
#define TORC_SETEVENTS "SETEVENTS"
#define TORC_AUTHENTICATE "AUTHENTICATE"
#define TORC_SAVECONF "SAVECONF"
#define TORC_SIGNAL "SIGNAL"
#define TORC_MAPADDRESS "MAPADDRESS"
#define TORC_GETINFO "GETINFO"
#define TORC_EXTENDCIRCUIT "EXTENDCIRCUIT"
#define TORC_SETCIRCUITPURPOSE "SETCIRCUITPURPOSE"
#define TORC_SETROUTERPURPOSE "SETROUTERPURPOSE"
#define TORC_ATTACHSTREAM "ATTACHSTREAM"
#define TORC_POSTDESCRIPTOR "POSTDESCRIPTOR"
#define TORC_REDIRECTSTREAM "REDIRECTSTREAM"
#define TORC_CLOSESTREAM "CLOSESTREAM"
#define TORC_CLOSECIRCUIT "CLOSECIRCUIT"
#define TORC_QUIT "QUIT"
#define TORC_USEFEATURE "USEFEATURE"
#define TORC_RESOLVE "RESOLVE"
#define TORC_PROTOCOLINFO "PROTOCOLINFO"
#define TORC_LOADCONF "LOADCONF"
#define TORC_TAKEOWNERSHIP "TAKEOWNERSHIP"
#define TORC_AUTHCHALLENGE "AUTHCHALLENGE"
#define TORC_DROPGUARDS "DROPGUARDS"
#define TORC_HSFETCH "HSFETCH"
#define TORC_ADD_ONION "ADD_ONION"
#define TORC_DEL_ONION "DEL_ONION"
#define TORC_HSPOST "HSPOST"
#define TORC_ONION_CLIENT_AUTH_ADD "ONION_CLIENT_AUTH_ADD"
#define TORC_ONION_CLIENT_AUTH_REMOVE "ONION_CLIENT_AUTH_REMOVE"
#define TORC_ONION_CLIENT_AUTH_VIEW "ONION_CLIENT_AUTH_VIEW"
#define TORC_DROPOWNERSHIP "DROPOWNERSHIP"
#define TORC_DROPTIMEOUTS "DROPTIMEOUTS"

typedef struct {
    int port;
    char* secret;
} torc_info;

typedef struct {
    torc_info* info;
    int socket;
    pthread_t listen_thread;
    bool alive;
    bool debug;
} torc;

int torc_connect_controller(torc* controller, torc_info info);
int torc_connect_debug_controller(torc* controller, torc_info info);
void torc_close_controller(torc* controller);

typedef struct {
    char* keyword;
    char** params;
    int param_len;
    int curr_param;
    int compiled_size;
} torc_command;

int torc_create_command(torc_command* command, char* keyword, int param_len);
int torc_add_option(torc_command* command, char* option);
char* torc_compile_command(torc_command* command);
void torc_send_str(torc* controller, char* data);
int torc_send_command(torc* controller, torc_command* command);
void torc_free_command(torc_command* command);

#endif //TORC_TORC_H
