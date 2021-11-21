#include "torc.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <libnet.h>

void* socket_listener(void* controller_ptr) {
    torc* controller = (torc*) controller_ptr;

    int n;
    while(controller->alive == true) { // loop while controller is active
        // check if socket can be read using select, if not continue
        fd_set fd;
        FD_ZERO(&fd);
        FD_SET(controller->socket, &fd);
        struct timeval timeout;
        timeout.tv_usec = 50 * 1000;
        n = select(controller->socket + 1, &fd, NULL, NULL, &timeout);
        if(n == -1) break;
        else if(n == 0) continue;
        if(!FD_ISSET(controller->socket, &fd)) {
            n = -1;
            break;
        }

        // read data
        // TODO: PARSE RESPONSES
        char buf[1024];
        if(recv(controller->socket, buf, sizeof(buf), 0) < 0) {
            n = -1;
            break;
        }
        if(controller->debug == true) if(fputs(buf, stdout) == EOF) printf("[TORC] ERROR PRINTING RESPONSE");
    }
    if(n == -1) perror("[TORC] ERROR READING SOCKET");

    return 0;
}

int torc_connect_controller(torc* controller, torc_info info) {
    controller->info = &info;

    // create socket stream
    controller->socket = socket(AF_INET, SOCK_STREAM, 0);
    if(controller->socket == -1) {
        perror("[TORC] FAILED TO CREATE SOCKET CONNECTION");
        return 1;
    }

    // bind socket to port and server address
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(info.port);
    if((connect(controller->socket, (struct sockaddr*) &servaddr, sizeof(servaddr))) != 0) {
        perror("[TORC] FAILED TO ESTABLISH SOCKET CONNECTION");
        return 1;
    }
    controller->alive = true;
    controller->debug = false;

    // create listener thread
    pthread_create(&controller->listen_thread, NULL, socket_listener, controller);

    return 0;
}

int torc_connect_debug_controller(torc* controller, torc_info info) {
    int n = torc_connect_controller(controller, info);
    if(n == 0) controller->debug = true;
    return n;
}

void torc_close_controller(torc* controller) {
    // kill and join listener thread
    controller->alive = false;
    pthread_join(controller->listen_thread, NULL);

    // close socket
    close(controller->socket);
}

int torc_create_command(torc_command* command, char* keyword, int param_len) {
    command->keyword = keyword;
    command->param_len = param_len;
    command->curr_param = 0;
    if(param_len > 0) command->params = malloc(sizeof(char*) * param_len);
    return 0;
}

int torc_add_option(torc_command* command, char* option) {
    if(command->curr_param >= command->param_len) return 1;
    command->params[command->curr_param++] = option;
    return 0;
}

char* torc_compile_command(torc_command* command) {
    // calculate the size of the output command string
    int keyword_size = strlen(command->keyword);
    int size = keyword_size + 2; // +2 for CRLF
    if(command->param_len > 0) {
        for(int i = 0; i < command->param_len; i++) {
            size += strlen(command->params[i]) + 1;
        }
    }

    // allocated space for string
    command->compiled_size = size;
    char* out = malloc(size + 1);
    if(out == NULL) return NULL;

    // concatenate keyword and options together
    int p = 0;
    memcpy(out, command->keyword, keyword_size);
    p += keyword_size;
    if(command->param_len > 0) {
        for(int i = 0; i < command->param_len; i++) {
            strcpy(out + p++, " ");
            int param_len = strlen(command->params[i]);
            memcpy(out + p, command->params[i], param_len);
            p += param_len;
        }
    }
    strcpy(out + p, "\r\n");

    return out;
}

void torc_send_str(torc* controller, char* data) {
    send(controller->socket, data, strlen(data), 0);
}

int torc_send_command(torc* controller, torc_command* command) {
    char* compiled = torc_compile_command(command);
    if(command == NULL) return 1;
    send(controller->socket, compiled, command->compiled_size, 0);
    free(compiled);
    return 0;
}

void torc_free_command(torc_command* command) {
    if(command->param_len > 0) free(command->params);
}