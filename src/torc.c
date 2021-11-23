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

static int expand_response_buffer(torc* controller) {
    // reallocate buffer to twice the previous size
    size_t prev_len = controller->responses_len;
    controller->responses = realloc(controller->responses, sizeof(torc_response*) * prev_len * 2);
    if(controller->responses == NULL) {
        perror("[TORC] FAILED TO EXPAND REPONSE BUFFER");
        return 1;
    }
    controller->responses_len *= 2;

    // move the data after the write pointer and change the read pointer
    void* src = controller->responses + sizeof(torc_response*) * controller->response_read_num;
    void* dst = src + sizeof(torc_response*) * prev_len;
    size_t size = dst - src;
    memcpy(dst, src, size); // copy
    memset(src, 0, size); // then zero where moved from
    controller->response_read_num += prev_len;

    return 0;
}

static int push_awaiting_response(torc* controller, torc_response* response) {
    if(controller->responses[controller->response_write_num] != NULL) {
        if(expand_response_buffer(controller) != 0) return 1;
    }

    controller->responses[controller->response_write_num++] = response;
    if(controller->response_write_num >= controller->responses_len) controller->response_write_num = 0;
    return 0;
}

static int expand_response_size(torc_response* response) {
    size_t size = response->buf_len * 2;
    response->data = realloc(response->data, size);
    if(response->data == NULL) {
        perror("FAILED TO REALLOCATE RESPONSE DATA");
        return 1;
    }
    response->curr = response->data + response->buf_len;
    response->buf_len = size;
    return 0;
}

// adds line length to response
static int add_line_len(torc_response* response, size_t length) {
    if(response->lines >= response->line_buf_len) { // expand line buffer
        size_t size = response->line_buf_len * 2;
        response->line_lens = realloc(response->line_lens, size * sizeof(unsigned int*));
        if(response->line_lens == NULL) {
            perror("[TORC] FAILED TO REALLOCATE LINE LENGTH BUFFER");
            return 1;
        }
        response->line_buf_len = size;
    }
    response->line_lens[response->lines++] = length;
    return 0;
}

static void* socket_listener(void* controller_ptr) {
    torc* controller = (torc*) controller_ptr;
    struct timeval timeout = { 0, 100000 };

    int n;
    unsigned int line_pos = 0;
    torc_response* curr_response = NULL;
    while(controller->alive) { // loop while controller is active
        // check if socket can be read using select, if not continue
        fd_set fd;
        FD_ZERO(&fd);
        FD_SET(controller->socket, &fd);
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

        // TODO: parse '+' line extensions
        // loop over data, add to response, and look for new line character
        if(curr_response != NULL) {
            for(int i = 0; i < read; i++) {
                if(curr_response == NULL) break; // if there is no longer a response to fulfill, break

                // amount of bytes written to data
                size_t size = curr_response->curr - curr_response->data;

                // make sure there is enough room in data buffer to write. if not, reallocate space
                if(size >= curr_response->buf_len) {
                    if(expand_response_size(curr_response) != 0) {
                        perror("FAILED TO EXPAND RESPONSE SIZE");
                        // TODO: ADD BREAKPOINT FOR THIS ERROR
                    }
                }

                // write to data buffer
                char c = buf[i];
                if(c != '\r') *(curr_response->curr++) = c;

                // if the 4th character of the line is a space (' '), then it is the last line.
                // it will be a dash ('-') if there is another line after
                if(line_pos == 3 && c == ' ') {
                    // mark response as received and read status code
                    curr_response->received = true;
                    curr_response->code[0] = *(curr_response->curr-4);
                    curr_response->code[1] = *(curr_response->curr-3);
                    curr_response->code[2] = *(curr_response->curr-2);
                    curr_response->error = curr_response->curr;
                    curr_response->ok = (curr_response->code[0] == '2' || curr_response->code[0] == '6') &&
                                        curr_response->code[1] == '5' &&
                                        curr_response->code[2] == '0';

                    // read remainder of line
                    while((c = buf[i+1]) != '\n') {
                        if(size >= curr_response->buf_len) {
                            if(expand_response_size(curr_response) != 0) {
                                perror("[TORC] FAILED TO EXPAND RESPONSE BUFFER");
                                // TODO: ADD BREAKPOINT FOR THIS ERROR
                            }
                        }
                        *(curr_response->curr++) = c;
                        if(c != '\r') {
                            line_pos++;
                            size++;
                        }
                        i++;
                    }
                    i++; // skip last return
                    line_pos++; // +1 character for char we read at pos 3
                    if(add_line_len(curr_response, line_pos) != 0) {
                        perror("[TORC] FAILED TO ADD LINE LENGTH");
                        // TODO: ADD BREAKPOINT FOR THIS ERROR
                    }
                    line_pos = 0;

                    // set length of data
                    curr_response->len = curr_response->data - curr_response->curr;

                    // null end the data
                    if(size >= curr_response->buf_len) {
                        if(expand_response_size(curr_response) != 0) {
                            perror("[TORC] FAILED TO EXPAND RESPONSE BUFFER");
                            // TODO: ADD BREAKPOINT FOR THIS ERROR
                        }
                    }
                    *(curr_response->curr) = 0; // dont increment cursor bc NULL isn't actually part of the data

                    // reset cursor
                    curr_response->curr = curr_response->data;

                    // pop next response
                    curr_response = pop_awaiting_response(controller);
                    continue;
                }

                if(c == '\n') {
                    if(curr_response != NULL) {
                        if(add_line_len(curr_response, line_pos) != 0) {
                            perror("[TORC] FAILED TO ADD LINE LENGTH");
                            // TODO: ADD BREAKPOINT FOR THIS ERROR
                        }
                    }
                    line_pos = 0;
                } else if(c != '\r') line_pos++; // skip \r
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

torc_info torc_default_addr_info(void) {
    torc_info info = { "127.0.0.1", 9051 };
    return info;
}

int torc_connect_controller(torc* controller, torc_info info) {
    controller->info = info;

    // create response list with default length of 10
    controller->responses_len = 10;
    controller->responses = calloc(controller->responses_len, sizeof(torc_response*));
    if(controller->responses == NULL) {
        perror("[TORC] FAILED TO ALLOCATE RESPONSE BUFFER");
        return 1;
    }
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
    servaddr.sin_addr.s_addr = inet_addr(info.addr);
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
    // send quit to server and kill immediately
    torc_command quit_command;
    torc_create_command(&quit_command, TORC_QUIT, 0);
    torc_send_command_async(controller, &quit_command);

    // kill and join listener thread
    controller->alive = false;
    pthread_join(controller->listen_thread, NULL);

    torc_free_command(&quit_command);
    free(controller->responses);

    // close socket
    close(controller->socket);
}

int torc_create_command(torc_command* command, char* keyword, int param_len) {
    command->keyword = keyword;
    command->param_len = param_len;
    command->curr_param = 0;

    command->response.received = false;
    command->response.lines = 0;
    command->response.line_buf_len = 4; // default line buffer size of 4;
    command->response.line_lens = calloc(command->response.line_buf_len, sizeof(unsigned int));
    if(command->response.line_lens == NULL) {
        perror("[TORC] FAILED TO ALLOCATE LINE LEN BUFFER");
        return 1;
    }

    command->response.buf_len = 64; // default response buffer size of 64
    command->response.data = calloc(command->response.buf_len, sizeof(char));
    if(command->response.data == NULL) {
        free(command->response.line_lens);
        perror("[TORC] FAILED TO ALLOCATE RESPONSE BUFFER");
        return 1;
    }
    command->response.curr = command->response.data;

    command->response.key_vals_len = 4;
    command->response.key_vals = calloc(command->response.key_vals_len, sizeof(torc_key_value*));
    if(command->response.key_vals == NULL) {
        free(command->response.line_lens);
        free(command->response.data);
        perror("[TORC] FAILED TO ALLOCATE KEY_VALUE BUFFER");
        return 1;
    }
    command->response.key_vals_num = 0;

    if(param_len > 0) {
        command->params = calloc((size_t) param_len, sizeof(char*));
        if(command->params == NULL) {
            free(command->response.line_lens);
            free(command->response.data);
            free(command->response.key_vals);
            perror("[TORC] FAILED TO ALLOCATE PARAMETER BUFFER");
            return 1;
        }
    }
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
    if(push_awaiting_response(controller, &command->response) != 0) {
        perror("[TORC] FAILED TO PUSH RESPONSE TO BUFFER");
        return 1;
    }

    free(compiled); // make sure to free compiled
    return 0;
}

int torc_send_command(torc* controller, torc_command* command) {
    if(torc_send_command_async(controller, command) != 0) return 1;
    while(!command->response.received); // TODO: ADD TIMEOUT FOR RESPONSE
    return 0;
}

static void torc_free_key_value(torc_key_value* key_value) {
    free(key_value->key);
    free(key_value->value);
    free(key_value);
}

void torc_free_command(torc_command* command) {
    if(command->param_len > 0) free(command->params);
    free(command->response.data);
    free(command->response.line_lens);
    for(int i = 0; i < command->response.key_vals_num; i++) torc_free_key_value(command->response.key_vals[i]);
    free(command->response.key_vals);
}

// returns the starting point of the line in the data buffer
char* torc_get_line(torc_response* response, size_t line) {
    char* pos = response->data + line; // the amount of returns between the lines are = to the line number (trust me, i swear)
    for(int i = 0; i < line; i++) {
        pos += response->line_lens[i];
    }
    pos += 4; // skip the status code at the beginning of the line
    return pos;
}

static torc_key_value* torc_get_key_value(char* start, size_t len, bool dquote /*whether to remove dquotes*/) {
    char* curr = start;
    torc_key_value* key_value = malloc(sizeof(torc_key_value));
    if(key_value == NULL) {
        perror("[TORC] FAILED TO ALLOCATE KEY_VALUE");
        return NULL;
    }

    key_value->key = calloc(len, sizeof(char));
    char* p = key_value->key;
    if(dquote) len--;
    while(curr < start + len - 4) { // -4 for skipping status code at the beginning of the line
        if(*curr == '=') {
            key_value->value = calloc(len + start - curr + 1, sizeof(char)); // +1 for null ending string
            *p = 0; // null end key
            p = key_value->value;
            curr++;
            if(dquote) curr++;
        } else *(p++) = *(curr++);
    }
    *p = 0; // null end value

    return key_value;
}

static int torc_add_key_value_to_response(torc_response* response, torc_key_value* key_value) {
    if(response->key_vals_num >= response->key_vals_len) { // expand line buffer
        size_t size = response->key_vals_len * 2;
        response->key_vals = realloc(response->key_vals, size * sizeof(torc_key_value*));
        if(response->key_vals == NULL) {
            perror("[TORC] FAILED TO REALLOCATE KEY_VALUE BUFFER");
            return 1;
        }
        response->key_vals_len = size;
    }
    response->key_vals[response->key_vals_num++] = key_value;
    return 0;
}

// key value freed when command response is freed
static torc_key_value* torc_get_key_value_from_line_optional_dquote(torc_response* response, size_t line, bool dquote) {
    torc_key_value* key_value = torc_get_key_value(torc_get_line(response, line), response->line_lens[line], dquote);
    if(key_value == NULL) {
        perror("[TORC] FAILED TO GET KEY_VALUE FROM LINE");
        return NULL;
    }
    if(torc_add_key_value_to_response(response, key_value) != 0) {
        perror("[TORC] FAILED TO ADD KEY_VALUE TO RESPONSE");
        // non fatal error
    }
    return key_value;
}

torc_key_value* torc_get_key_value_from_line(torc_response* response, size_t line) {
    return torc_get_key_value_from_line_optional_dquote(response, line, false);
}

torc_key_value* torc_get_key_value_from_line_dquote(torc_response* response, size_t line) {
    return torc_get_key_value_from_line_optional_dquote(response, line, true);
}

void torc_print_line(torc_response* response, size_t line) {
    char* p = torc_get_line(response, line);
    for(int i = 0; i < response->line_lens[line]; i++) {
        printf("%c", *(p++));
    }
}

bool torc_auto_authenticate(torc* controller) {
    return false;
}

bool torc_cookie_authenticate(torc* controller) {
    return false;
}

bool torc_safe_cookie_authenticate(torc* controller) {
    return false;
}

bool torc_password_authenticate(torc* controller, char* password) {
    // quote password
    size_t size = strlen(password) + 3;
    char* quoted = malloc(size);
    *quoted = '"';
    memcpy(quoted + 1, password, size - 3);
    *(quoted + size - 2) = '"';
    *(quoted + size - 1) = 0;

    // send command
    torc_command command;
    torc_create_command(&command, TORC_AUTHENTICATE, 1);
    torc_add_option(&command, quoted);
    torc_send_command(controller, &command);

    bool authenticated = command.response.ok;

    // free
    torc_free_command(&command);
    free(quoted);

    return authenticated;
}
