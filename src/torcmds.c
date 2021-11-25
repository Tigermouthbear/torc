#include "torcmds.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

static char* write_flags(int flags, int num, ...) {
    // copy varargs to array
    const char* flag_names[num];
    va_list args;
    va_start(args, num);
    for(int i = 0; i < num; i++) {
        flag_names[i] = va_arg(args, char*);
    }
    va_end(args);

    // find size of flag string
    size_t flags_len = 0;
    bool first = true;
    for(int i = 0; i < num; i++) {
        int mask = 1 << i;
        if((flags & mask) == mask) {
            if(first) first = false;
            else flags_len++;
            flags_len += strlen(flag_names[i]);
        }
    }

    // concat flags together
    char* flag_str = malloc(flags_len + 1);
    char* curr = flag_str;
    first = true;
    if(flag_str == NULL) {
        perror("[TORC] FAILED TO CREATE FLAG LIST");
        return NULL;
    }
    for(int i = 0; i < num; i++) {
        int mask = 1 << i;
        if((flags & mask) == mask) {
            if(first) first = false;
            else *(curr++) = ',';
            size_t len = strlen(flag_names[i]);
            memcpy(curr, flag_names[i], len);
            curr += len;
        }
    }
    *curr = 0;

    return flag_str;
}

static int read_flags(char* flags, int num, ...) {
    // copy varargs to array
    const char* flag_names[num];
    va_list args;
    va_start(args, num);
    for(int i = 0; i < num; i++) {
        flag_names[i] = va_arg(args, char*);
    }
    va_end(args);

    // create flag, and temp buffer for comparing strings
    int flag = TORC_FLAGS_NONE;
    size_t flags_len = strlen(flags);
    char* curr = flags;
    char temp[flags_len + 1];
    memset(temp, 0, flags_len + 1);
    int offset = 0;

    // read flags
    char c;
    while((c = *(curr++)) != 0) {
        if(c == ',') {
            // check if any flags match the string, if they do: add the flag
            for(int i = 0; i < num; i++) {
                if(strcmp(temp, flag_names[i]) == 0) {
                    flag |= 1 << i;
                }
            }

            // reset the temp buffer
            offset = 0;
            memset(temp, 0, flags_len + 1);
        } else temp[offset++] = c;
    }

    // add last one
    // check if any flags match the string, if they do: add the flag
    for(int i = 0; i < num; i++) {
        if(strcmp(temp, flag_names[i]) == 0) {
            flag |= 1 << i;
        }
    }

    return flag;
}

static char* concat(char* prefix, char* suffix) {
    size_t prefix_len = strlen(prefix);
    size_t suffix_len =  strlen(suffix);
    char* out = malloc(prefix_len + suffix_len + 1);
    if(out == NULL) {
        perror("[TORC] FAILED TO CONCAT STRINGS");
        return NULL;
    }
    memcpy(out, prefix, prefix_len);
    memcpy(out + prefix_len, suffix, suffix_len);
    out[prefix_len + suffix_len] = 0;
    return out;
}

torc_protocol_info_response torc_get_protocol_info(torc* controller, torc_command* command) {
    // create and send command
    torc_protocol_info_response response = { false };
    if(torc_create_command(command, TORC_PROTOCOLINFO, 0) != 0) {
        perror("[TORC] FAILED TO CREATE PROTOCOL INFO COMMAND");
        return response;
    }
    if(torc_send_command(controller, command) != 0) {
        perror("[TORC] FAILED TO SEND PROTOCOL INFO COMMAND");
        return response;
    }
    response.sent = true;

    // read response
    if(!command->response.ok) return response;
    for(int i = 0; i < command->response.values_num; i++) {
        torc_value* value = command->response.values[i];
        if(value->type == TORC_TYPE_KEY_VALUE) {
            if(strcmp(value->key, "VERSION Tor") == 0) {
                response.version = value->value;
            } else if(strcmp(value->key, "AUTH METHODS") == 0) {
                response.auth_methods = read_flags(value->value, 3, "HASHEDPASSWORD", "COOKIE", "SAFECOOKIE");
            } else if(strcmp(value->key, "COOKIEFILE") == 0) {
                response.cookie_file = value->value;
            }
        }
    }

    return response;
}

torc_add_onion_response torc_add_new_onion(torc* controller, torc_command* command, char* port, int flags) {
    torc_add_onion_response response = { false };
    if(torc_create_command(command, TORC_ADD_ONION, flags != TORC_FLAGS_NONE ? 3 : 2) != 0) {
        perror("[TORC] FAILED TO CREATE ADD NEW ONION COMMAND");
        return response;
    }
    if(torc_add_option(command, "NEW:BEST") != 0) {
        perror("[TORC] FAILED TO ADD OPTION TO ADD NEW ONION COMMAND");
        return response;
    }

    // add port target to command
    char* port_target = concat("PORT=", port);
    if(port_target == NULL) {
        perror("[TORC] FAILED TO ALLOCATE MEM FOR PORT OPTION IN ADD NEW ONION COMMAND");
        return response;
    }
    if(torc_add_option(command, port_target) != 0) {
        perror("[TORC] FAILED TO ADD PORT OPTION TO ADD NEW ONION COMMAND");
        return response;
    }

    // add flags to command
    char* flag_str = NULL;
    if(flags != TORC_FLAGS_NONE) {
        char* flag_list = write_flags(flags, 4, "DiscardPK", "Detach", "V3Auth", "NonAnonymous");
        flag_str = concat("Flags=", flag_list);
        if(flag_str == NULL) {
            perror("[TORC] FAILED TO ALLOCATE MEM FOR FLAG OPTION IN ADD NEW ONION COMMAND");
            free(port_target);
            return response;
        }
        free(flag_list);

        if(torc_add_option(command, flag_str) != 0) {
            perror("[TORC] FAILED TO ADD FLAG OPTION TO ADD NEW ONION COMMAND");
            return response;
        }
    }

    // send command
    if(torc_send_command(controller, command) != 0) {
        perror("[TORC] FAILED TO SEND ADD NEW ONION COMMAND");
        return response;
    }
    response.sent = true;
    free(port_target);
    if(flags != TORC_FLAGS_NONE) free(flag_str);

    // read response
    if(!command->response.ok) return response;
    for(int i = 0; i < command->response.values_num; i++) {
        torc_value* value = command->response.values[i];
        if(value->type == TORC_TYPE_KEY_VALUE) {
            if(strcmp(value->key, "ServiceID") == 0) {
                response.service_id = value->value;
            } else if(strcmp(value->key, "PrivateKey") == 0) {
                response.private_key = value->value;
            }
        }
    }

    return response;
}
