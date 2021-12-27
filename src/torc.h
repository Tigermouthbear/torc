#ifndef TORC_TORC_H
#define TORC_TORC_H

#include <stdbool.h>
#include <pthread.h>

#define TORC_TYPE_KEY_VALUE 0
#define TORC_TYPE_VALUE 1

#define TORC_QUIT "QUIT"

// dumb simple debug logging
#include <stdio.h>
#include <errno.h>
extern int errno;
#ifndef NDEBUG
#define TORC_LOG_ERROR(...) {fprintf(stderr, "[TORC] ");fprintf(stderr, __VA_ARGS__);fprintf(stderr, ": %s\n", strerror(errno));}
#define TORC_LOG_DEBUG(...) {fprintf(stdout, "[TORC] ");fprintf(stdout, __VA_ARGS__);}
#else
#define TORC_LOG_ERROR(...)
#define TORC_LOG_DEBUG(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool nix; // whether this is using a unix socket or a regular socket connection
    char* addr;
    int port;
} torc_info;

typedef struct {
    int type; // types: TYPE_KEY_VALUE and TYPE_VALUE
    char* key; // only present when TYPE is TYPE_KEY_VALUE
    char* value;
} torc_value;

typedef struct {
    pthread_mutex_t lock; // lock to prevent multi thread variable errors
    bool received;
    bool ok;
    char code[3];
    char* error; // the location of the final error message ("OK" if no error)

    size_t len; // length of data in buffer
    char* data;
    char* curr;
    size_t buf_len; // length of data buffer, not actual length of data

    unsigned int lines; // lines in response
    unsigned int* line_lens; // characters of each line
    size_t line_buf_len; // length of line length buffer

    unsigned int values_len;
    torc_value** values;
    unsigned int values_num;
} torc_response;

typedef struct {
    char* keyword;
    size_t compiled_len;
    torc_response response;

    char** params;
    unsigned int param_len;
    unsigned int curr_param;
} torc_command;

typedef struct {
    pthread_mutex_t lock; // lock to prevent multi thread variable errors

    torc_info info;

    int socket;
    pthread_t listen_thread;
    bool alive;

    torc_response** responses;
    size_t responses_len;
    size_t response_write_num;
    size_t response_read_num;
} torc;

torc_info torc_default_addr_info(void);
torc_info torc_create_unix_info(const char* location);
int torc_connect_controller(torc* controller, torc_info info);
bool torc_is_alive(torc* controller);
void torc_close_controller(torc* controller);

int torc_create_command(torc_command* command, char* keyword, int param_len);
int torc_add_option(torc_command* command, char* option);
char* torc_compile_command(torc_command* command);

int torc_send_command_async(torc* controller, torc_command* command);
void torc_wait_for_response(torc_command* command);
int torc_send_command(torc* controller, torc_command* command);
void torc_free_command(torc_command* command);

char* torc_get_line_start(torc_response* response, size_t line);
void torc_print_line(torc_response* response, size_t line);

#ifdef __cplusplus
}
#endif
#endif //TORC_TORC_H
