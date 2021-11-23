#include "torcmds.h"

#include <string.h>
#include <stdio.h>

torc_protocol_info_response torc_send_protocol_info_command(torc* controller, torc_command* command) {
    torc_create_command(command, TORC_PROTOCOLINFO, 0);
    torc_send_command(controller, command);

    // read response
    torc_protocol_info_response response  = { NULL, NULL, NULL };
    if(command->response.ok && command->response.lines > 2) {
        for(int i = 1; i < command->response.lines - 1; i++) {
            torc_key_value* key_value = torc_get_key_value_from_line(&command->response, i);
            if(strcmp(key_value->key, "VERSION Tor") == 0) {
                response.version = torc_get_key_value_from_line_dquote(&command->response, i)->value;
            } else if(strcmp(key_value->key, "AUTH METHODS") == 0) {
                response.auth_methods = key_value->value;
            } else if(strcmp(key_value->key, "COOKIEFILE") == 0) {
                response.cookie_file = key_value->value;
            }
        }
    }

    return response;
}