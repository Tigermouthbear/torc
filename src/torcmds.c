#include "torcmds.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

torc_protocol_info_response torc_get_protocol_info(torc* controller, torc_command* command) {
    torc_create_command(command, TORC_PROTOCOLINFO, 0);
    torc_send_command(controller, command);

    // read response
    torc_protocol_info_response response;
    for(int i = 0; i < command->response.values_num; i++) {
        torc_value* value = command->response.values[i];
        if(value->type == TORC_TYPE_KEY_VALUE) {
            if(strcmp(value->key, "VERSION Tor") == 0) {
                response.version = value->value;
            } else if(strcmp(value->key, "AUTH METHODS") == 0) {
                response.auth_methods = value->value;
            } else if(strcmp(value->key, "COOKIEFILE") == 0) {
                response.cookie_file = value->value;
            }
        }
    }

    return response;
}

torc_add_onion_response torc_add_new_onion(torc* controller, torc_command* command, char* port, int flags) {
    int params = 2;
    if(flags != TORC_FLAGS_NONE) params++;

    torc_create_command(command, TORC_ADD_ONION, params);
    torc_add_option(command, "NEW:BEST");

    size_t port_len = strlen(port);
    char* port_target = calloc(port_len + 6, sizeof(char));
    if(port_target == NULL) {
        perror("[TORC] FAILED TO CREATE ADD NEW ONION COMMAND");
        // TODO: HANDLE ERROR HERE
    }
    strncat(port_target, "PORT=", 5);
    strncat(port_target, port, port_len);
    torc_add_option(command, port_target);

    char* flag_str = NULL;
    if(flags != TORC_FLAGS_NONE) {
        // TODO: make a macro or function to do this flag stuff
        const char* discard_pk = "DiscardPK"; // strlen = 9
        const char* detach = "Detach"; // strlen = 6
        const char* v3_auth = "V3Auth"; // strlen = 6
        const char* non_anonymous = "NonAnonymous"; // strlen = 12

        // find size of flag string
        size_t flags_len = 6;
        bool first = true;
        if((flags & TORC_FLAGS_DISCARD_PK) == TORC_FLAGS_DISCARD_PK) {
            first = false;
            flags_len += 9;
        }
        if((flags & TORC_FLAGS_DETACH) == TORC_FLAGS_DETACH) {
            if(first) first = false;
            else flags_len++;
            flags_len += 6;
        }
        if((flags & TORC_FLAGS_V3AUTH) == TORC_FLAGS_V3AUTH) {
            if(first) first = false;
            else flags_len++;
            flags_len += 6;
        }
        if((flags & TORC_FLAGS_NONANONYMOUS) == TORC_FLAGS_NONANONYMOUS) {
            if(first) first = false;
            else flags_len++;
            flags_len += 12;
        }

        // concat string
        flag_str = calloc(flags_len + 1, sizeof(char));
        strncat(flag_str, "Flags=", 6);
        first = true;
        if((flags & TORC_FLAGS_DISCARD_PK) == TORC_FLAGS_DISCARD_PK) {
            first = false;
            strncat(flag_str, discard_pk, strlen(discard_pk));
        }
        if((flags & TORC_FLAGS_DETACH) == TORC_FLAGS_DETACH) {
            if(first) first = false;
            else strncat(flag_str, ",", 1);
            strncat(flag_str, detach, strlen(detach));
        }
        if((flags & TORC_FLAGS_V3AUTH) == TORC_FLAGS_V3AUTH) {
            if(first) first = false;
            else strncat(flag_str, ",", 1);
            strncat(flag_str, v3_auth, strlen(v3_auth));
        }
        if((flags & TORC_FLAGS_NONANONYMOUS) == TORC_FLAGS_NONANONYMOUS) {
            if(first) first = false;
            else strncat(flag_str, ",", 1);
            strncat(flag_str, non_anonymous, strlen(non_anonymous));
        }

        torc_add_option(command, flag_str);
    }

    torc_send_command(controller, command);
    free(port_target);
    if(flag_str != NULL) free(flag_str);

    // read response
    torc_add_onion_response response;
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