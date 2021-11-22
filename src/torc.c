#include "torc.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <libnet.h>

static torc_response* pop_awaiting_response(torc* controller) {
    // get response and erase from list
    torc_response* response = controller->responses[controller->response_read_num];
    if(response == NULL) return NULL;
    controller->responses[controller->response_read_num] = NULL;

    // increment position
    controller->response_read_num++;
    if(controller->response_read_num >= controller->responses_len) controller->response_read_num = 0;

    return response;
}

static void expand_response_buffer(torc* controller) {
    // reallocate buffer to twice the previous size
    int prev_len = controller->responses_len;
    controller->responses = realloc(controller->responses, sizeof(torc_response*) * controller->responses_len * 2);
    controller->responses_len *= 2;

    // move the data after the write pointer and change the read pointer
    void* src = controller->responses + sizeof(torc_response*) * controller->response_read_num;
    void* dst = src + sizeof(torc_response*) * prev_len;
    size_t size = dst - src;
    memcpy(dst, src, size);
    memset(src, 0, size);
    controller->response_read_num += prev_len;
}

static void push_awaiting_response(torc* controller, torc_response* response) {
    if(controller->responses[controller->response_write_num] != NULL) {
        expand_response_buffer(controller);
    }

    controller->responses[controller->response_write_num++] = response;
    if(controller->response_write_num >= controller->responses_len) controller->response_write_num = 0;
}

static bool is_reply_end(const char* data, const char* curr) {
    size_t size = curr - data;
    return size >= 8 &&
           *(curr-1) == '\n' &&
           *(curr-2) == '\r' &&
           *(curr-3) == 'K' &&
           *(curr-4) == 'O' &&
           *(curr-5) == ' ' &&
           *(curr-6) == '0' &&
           *(curr-7) == '5' &&
           (*(curr-8) == '2' || *(curr-8) == '6');
}

static bool is_bad_status_code(const char code[3]) {
    return !(code[0] == '2' || code[0] == '6') || code[1] != '5' || code[2] != '0';
}

static void* socket_listener(void* controller_ptr) {
    torc* controller = (torc*) controller_ptr;

    int n;
    int offset = 0;
    char curr_status_code[3];
    torc_response* curr_response = NULL;
    while(controller->alive) { // loop while controller is active
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
            n = -1; // mark n as -1 for error
            break;
        }

        // read available data into buffer
        char buf[1024];
        ssize_t read = recv(controller->socket, buf, sizeof(buf), 0);
        if(read < 0) {
            n = -1; // mark n as -1 for error
            break;
        }

        // find / verify there is a response
        if(curr_response == NULL) curr_response = pop_awaiting_response(controller);

        // loop over data, add to response, and look for new line character
        if(curr_response != NULL) {
            for(int i = 0; i < read; i++) {
                if(curr_response == NULL) break; // if there is no longer a response to fulfill, break

                char c = buf[i];
                *(curr_response->curr++) = c;

                if(offset < 3) curr_status_code[offset] = c;
                if(is_reply_end(curr_response->data, curr_response->curr)|| (offset == 2 && is_bad_status_code(curr_status_code))) {
                    // TODO: FINISH READING ERROR MESSAGE ON BAD STATUS CODE
                    // mark response as received and find next response
                    curr_response->received = true;
                    curr_response = pop_awaiting_response(controller);
                } else if(i >= curr_response->len) { // expand response data if needed
                    int size = curr_response->len * 2;
                    curr_response->data = realloc(curr_response->data, size);
                    curr_response->curr = curr_response->data + curr_response->len + 1;
                    curr_response->len = size;
                }

                if(c == '\n') offset = 0;
                else offset++;
            }
        }/* else {
            // if we get here, this isn't a response to a command, but an asynchronous message from the server
            // currently this library only supports call and response, it will likely be added later
        }*/

        if(controller->debug) if(fputs(buf, stdout) == EOF) printf("[TORC] ERROR PRINTING RESPONSE");
    }
    if(n == -1) perror("[TORC] ERROR READING SOCKET");

    return 0;
}

torc_info torc_default_addr_info() {
    torc_info info = { "127.0.0.1", 9051 };
    return info;
}

int torc_connect_controller(torc* controller, torc_info info) {
    controller->info = info;

    // create response list with default length of 10
    controller->responses = malloc(sizeof(torc_response*) * 10);
    controller->responses_len = 10;
    controller->response_read_num = 0;
    controller->response_write_num = 0;

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

void torc_close_controller(torc* controller) {
    // kill and join listener thread
    controller->alive = false;
    pthread_join(controller->listen_thread, NULL);

    // free response list
    free(controller->responses);

    // close socket
    close(controller->socket);
}

int torc_create_command(torc_command* command, char* keyword, int param_len) {
    command->keyword = keyword;
    command->param_len = param_len;
    command->curr_param = 0;
    command->response.received = false;
    command->response.len = 64; // default response size of 64
    command->response.data = malloc(command->response.len * sizeof(char));
    command->response.curr = command->response.data;
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
    size_t keyword_size = strlen(command->keyword);
    size_t size = keyword_size + 2; // +2 for CRLF
    if(command->param_len > 0) {
        for(int i = 0; i < command->param_len; i++) {
            size += strlen(command->params[i]) + 1;
        }
    }

    // allocated space for string
    command->compiled_len = size;
    char* out = malloc(size + 1);
    if(out == NULL) return NULL;

    // concatenate keyword and options together
    size_t p = 0;
    memcpy(out, command->keyword, keyword_size);
    p += keyword_size;
    if(command->param_len > 0) {
        for(int i = 0; i < command->param_len; i++) {
            strcpy(out + p++, " ");
            size_t param_len = strlen(command->params[i]);
            memcpy(out + p, command->params[i], param_len);
            p += param_len;
        }
    }
    strcpy(out + p, "\r\n");

    return out;
}

int torc_send_command_async(torc* controller, torc_command* command) {
    char* compiled = torc_compile_command(command);
    if(compiled == NULL) return 1; // failed to compile command

    // send compiled command over socket, then add to response pool
    send(controller->socket, compiled, command->compiled_len, 0);
    push_awaiting_response(controller, &command->response);

    free(compiled); // make sure to free compiled
    return 0;
}

int torc_send_command(torc* controller, torc_command* command) {
    if(torc_send_command_async(controller, command) != 0) return 1;
    while(!command->response.received);
    return 0;
}

void torc_free_command(torc_command* command) {
    if(command->param_len > 0) free(command->params);
    free(command->response.data);
}

char* torc_read_raw_response(torc_response* response) {
    size_t len = response->curr - response->data;
    char* raw = malloc(len + 1);
    memcpy(raw, response->data, len);
    raw[len] = 0;
    return raw;
}
