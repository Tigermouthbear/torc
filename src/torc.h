#ifndef TORC_TORC_H
#define TORC_TORC_H

#include <stdbool.h>
#include <pthread.h>
#include "torcmds.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char* addr;
    int port;
} torc_info;

typedef struct {
    bool received;
    bool ok;
    char code[3];
    char* error; // the location of the final error message ("OK" if no error)
    size_t len;
    char* data;
    char* curr;
    size_t buf_len; // length of data buffer, not actual length of data
    size_t lines; // lines in response
    size_t* line_lens; // characters of each line
    size_t line_buf_len;
} torc_response;

typedef struct {
    char* keyword;
    char** params;
    size_t param_len;
    size_t curr_param;
    size_t compiled_len;
    torc_response response;
} torc_command;

typedef struct {
    torc_info info;
    int socket;
    pthread_t listen_thread;
    bool alive;
    bool debug;
    torc_response** responses;
    size_t responses_len;
    size_t response_write_num;
    size_t response_read_num;
} torc;

torc_info torc_default_addr_info();
int torc_connect_controller(torc* controller, torc_info info);
void torc_close_controller(torc* controller);

int torc_create_command(torc_command* command, char* keyword, int param_len);
int torc_add_option(torc_command* command, char* option);
char* torc_compile_command(torc_command* command);

int torc_send_command_async(torc* controller, torc_command* command);
int torc_send_command(torc* controller, torc_command* command);
void torc_free_command(torc_command* command);

char* torc_get_line(torc_response* response, int line);
void torc_print_line(torc_response* response, int line); // debug function

// 'auto' authenticates with cookie, safe cookie, or none if possible
// all authentication functions return false on fail
// TODO: FINISH COOKIE AND AUTO AUTHENTICATION
bool torc_auto_authenticate(torc* controller);
bool torc_cookie_authenticate(torc* controller);
bool torc_safe_cookie_authenticate(torc* controller);
bool torc_password_authenticate(torc* controller, char* password);

#ifdef __cplusplus
}
#endif
#endif //TORC_TORC_H
