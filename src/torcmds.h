#ifndef TORC_TORCMDS_H
#define TORC_TORCMDS_H

#include "torc.h"

#define TORC_SETCONF "SETCONF"
#define TORC_RESETCONF "RESETCONF"
#define TORC_GETCONF "GETCONF"
#define TORC_SETEVENTS "SETEVENTS"
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

#define TORC_FLAGS_NONE 0

#ifdef __cplusplus
extern "C" {
#endif

// AUTHENTICATE and QUIT command handled in torc.h
// the rest of the commands will be implemented here

// IMPLEMENTATION OF PROTOCOLINFO
// TORC_FLAGS_NONE means no auth
#define TORC_FLAGS_HASHEDPASSWORD 1
#define TORC_FLAGS_COOKIE 2
#define TORC_FLAGS_SAFECOOKIE 4
typedef struct {
    bool sent; // whether the command was successfully sent, users SHOULD check this to make sure the command went through
    char* version;
    int auth_methods;
    char* cookie_file;
} torc_protocol_info_response;
torc_protocol_info_response torc_get_protocol_info(torc* controller, torc_command* command);

// IMPLEMENTATION OF ADD_ONION
#define TORC_FLAGS_DISCARD_PK 1
#define TORC_FLAGS_DETACH 2
#define TORC_FLAGS_V3AUTH 4
#define TORC_FLAGS_NONANONYMOUS 8
typedef struct {
    bool sent;
    char* service_id;
    char* private_key;
} torc_add_onion_response;
torc_add_onion_response torc_add_new_onion(torc* controller, torc_command* command, char* port, int flags);
torc_add_onion_response torc_add_onion(torc* controller, torc_command* command, char* port, char* private_key, int flags); // TODO: THIS, ALSO ADD V3 ONION PK GENERATION

#ifdef __cplusplus
}
#endif

#endif //TORC_TORCMDS_H
