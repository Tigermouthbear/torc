#include "torcmds.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <openssl/hmac.h>

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

static char* dquote(char* string) {
    size_t size = strlen(string) + 3;
    char* quoted = malloc(size);
    if(quoted == NULL) {
        perror("[TORC] FAILED TO QUOTE STRING");
        return NULL;
    }
    *quoted = '"';
    memcpy(quoted + 1, string, size - 3);
    *(quoted + size - 2) = '"';
    *(quoted + size - 1) = 0;
    return quoted;
}

static bool contains(char* string, char c) {
    char* p = string;
    while(*p != 0) {
        if(*p == c) return true;
        p++;
    }
    return false;
}

const char* hex = "0123456789ABCDEF";
static void write_hex(char* dst, char b) {
    *dst = hex[(b >> 4) & 0xF];
    *(dst + 1) = hex[b & 0xF];
}
static int read_hex(char c) {
    if(c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if(c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if(c >= '0' && c <= '9') {
        return c - '0';
    }
    return 0;
}
static int read_double_hex(char* src) {
    return (read_hex(src[0]) << 4) | read_hex(src[1]);
}

static char* rand_bytes(size_t size) {
    unsigned char* bytes = malloc(size);
    if(bytes == NULL) return NULL;
    for(int i = 0; i < size; i++) {
        bytes[i] = rand() % 256;
    }
    return (char*) bytes;
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
    response.auth_methods = TORC_FLAGS_NONE;
    for(int i = 0; i < command->response.values_num; i++) {
        torc_value* value = command->response.values[i];
        if(value->type == TORC_TYPE_KEY_VALUE) {
            if(strcmp(value->key, "VERSION Tor") == 0) {
                response.version = value->value;
            } else if(strcmp(value->key, "AUTH METHODS") == 0) { // COOKIEFILE MIGHT BE AFTER FLAGS
                if(contains(value->value, ' ')) { // parse cookiefile flag
                    // read flags
                    char* p = value->value;
                    while(*p != ' ') {
                        p++;
                    }
                    size_t flags_size = p - value->value;
                    char* flags = malloc(flags_size + 1);
                    if(flags == NULL) {
                        perror("[TORC] FAILED TO ALLOCATE FLAG BUFFER FOR PROTOCOL INFO RESPONSE");
                        continue;
                    }
                    memcpy(flags, value->value, flags_size);
                    flags[flags_size] = 0;
                    response.auth_methods = read_flags(flags, 3, "HASHEDPASSWORD", "COOKIE", "SAFECOOKIE");
                    free(flags);

                    // read cookiefile
                    p += 13;
                    response.cookie_file = p;
                    while(*p != '"') p++;
                    *p = 0; // just replace dqoute at the end with null
                } else {
                    response.auth_methods = read_flags(value->value, 3, "HASHEDPASSWORD", "COOKIE", "SAFECOOKIE");
                }
            }
        }
    }

    return response;
}

torc_authchallenge_response torc_authchallenge(torc* controller, torc_command* command, char* nonce) {
    torc_authchallenge_response response = { false };
    if(torc_create_command(command, TORC_AUTHCHALLENGE, 2) != 0) {
        perror("[TORC] FAILED TO CREATE AUTHCHALLENGE COMMAND FOR SAFECOOKIE AUTHENTICATION");
        return response;
    }
    if(torc_add_option(command, "SAFECOOKIE") != 0) {
        perror("[TORC] FAILED TO CREATE AUTHCHALLENGE COMMAND FOR SAFECOOKIE AUTHENTICATION");
        return response;
    }
    if(torc_add_option(command, nonce) != 0) {
        perror("[TORC] FAILED TO CREATE AUTHCHALLENGE COMMAND FOR SAFECOOKIE AUTHENTICATION");
        return response;
    }
    if(torc_send_command(controller, command) != 0) {
        perror("[TORC] FAILED TO SEND AUTHCHALLENGE COMMAND FOR SAFECOOKIE AUTHENTICATION");
        return response;
    }
    response.sent = true;

    // read response
    if(!command->response.ok) return response;

    // read serverhash
    char* p = command->response.data;
    while(*p != '=' && *p != 0) p++;
    if(*p == 0) return response;
    response.server_hash = ++p;
    while(*p != ' ' && *p != 0) p++;
    if(*p == 0) return response;
    *(p++) = 0;

    // read servernonce
    while(*p != '=' && *p != 0) p++;
    if(*p == 0) return response;
    response.server_nonce = ++p;

    return response;
}

bool none_authenticate(torc* controller) {
    torc_command command;
    if(torc_create_command(&command, TORC_AUTHENTICATE, 0) != 0) return false;
    if(torc_send_command(controller, &command) != 0) {
        torc_free_command(&command);
        return false;
    }

    bool authenticated = command.response.ok;
    torc_free_command(&command);
    return authenticated;
}

static char* read_cookiefile_secret(torc_protocol_info_response protocol_info) {
    if(protocol_info.cookie_file == NULL)  {
        perror("[TORC] FAILED TO READ COOKIEFILE, COULD NOT FIND COOKIEFILE PARAMETER IN RESPONSE");
        return NULL;
    }

    // open file and get length
    FILE* file = fopen(protocol_info.cookie_file, "rb"); // open in read binary mode
    if(file == NULL) {
        perror("[TORC] FAILED TO OPEN COOKIEFILE FOR AUTHENTICATION");
        return NULL;
    }
    fseek(file, 0, SEEK_END); // seek to end
    size_t length = ftell(file); // write file length
    rewind(file); // seek to beginning

    // read file into byte array (+1 for null ending)
    char* bytes = malloc(length + 1);
    if(bytes == NULL) {
        perror("[TORC] FAILED TO ALLOCATE MEM FOR BYTES FOR COOKIEFILE READING");
        return NULL;
    }
    fread(bytes, length, 1, file);
    fclose(file);
    bytes[length] = 0;

    return bytes;
}

static char* read_cookiefile_secret_hex(torc_protocol_info_response protocol_info) {
    char* bytes = read_cookiefile_secret(protocol_info);
    if(bytes == NULL) return NULL;

    // convert to hex
    char* hex_bytes = malloc(strlen(bytes) * 2 + 1);
    if(hex_bytes == NULL) {
        free(bytes);
        perror("[TORC] FAILED TO ALLOCATE MEM FOR HEX BYTES FOR COOKIEFILE READING");
        return NULL;
    }
    char* b = bytes;
    char* p = hex_bytes;
    while(*b != 0) {
        write_hex(p, *b);
        p += 2;
        b++;
    }
    *p = 0;
    free(bytes);
    return hex_bytes;
}

bool cookie_authenticate(torc* controller, torc_protocol_info_response protocol_info) {
    // read secret from cookiefile
    char* secret = read_cookiefile_secret_hex(protocol_info);
    if(secret == NULL) return false;

    // send authenticate command
    torc_command command;
    if(torc_create_command(&command, TORC_AUTHENTICATE, 1) != 0) {
        free(secret);
        perror("[TORC] FAILED TO CREATE COMMAND FOR COOKIE AUTHENTICATION");
        return false;
    }
    if(torc_add_option(&command, secret) != 0) {
        torc_free_command(&command);
        free(secret);
        perror("[TORC] FAILED TO CREATE COMMAND FOR COOKIE AUTHENTICATION");
        return false;
    }
    if(torc_send_command(controller, &command) != 0) {
        torc_free_command(&command);
        free(secret);
        perror("[TORC] FAILED TO SEND COMMAND FOR COOKIE AUTHENTICATION");
        return false;
    }

    bool authenticated = command.response.ok;
    torc_free_command(&command);
    free(secret);
    return authenticated;
}

static char* safecookie_hmac_hex(const char* hash_constant, char* secret, size_t secret_size,
                             char* client_nonce, size_t client_nonce_size, char* server_nonce, size_t server_nonce_size) {
    // join all nonces and secret
    size_t all_size = secret_size + client_nonce_size + server_nonce_size;
    unsigned char* all = malloc(all_size);
    if(all == NULL) {
        perror("[TORC] FAILED TO ALLOCATE MSG BUFFER FOR HMAC");
        return NULL;
    }
    memcpy(all, secret, secret_size);
    memcpy(all + secret_size, client_nonce, client_nonce_size);
    memcpy(all + secret_size + client_nonce_size, server_nonce, server_nonce_size);

    // run hmac
    unsigned int hmac_size = 32;
    unsigned char* hmac = malloc(hmac_size); // hex sha246 output +1 for null ending
    if(hmac == NULL) {
        free(all);
        perror("[TORC] FAILED TO ALLOCATE OUT BUFFER FOR HMAC");
        return NULL;
    }
    hmac = HMAC(EVP_sha256(), hash_constant, (int) strlen(hash_constant), all, all_size, hmac, &hmac_size);
    free(all);

    // convert to hex
    char* out = malloc(hmac_size * 2 + 1);
    if(out == NULL) {
        free(hmac);
        perror("[TORC] FAILED TO ALLOCATE HEX BUFFER FOR HMAC");
        return NULL;
    }
    for(int i = 0; i < hmac_size; i++) {
        write_hex(out + i * 2, (char) hmac[i]);
    }
    out[hmac_size * 2] = 0;
    free(hmac);

    return out;
}

bool safe_cookie_authenticate(torc* controller, torc_protocol_info_response protocol_info) {
    // these are the keys which are used by tor to verify safecookie
    const char* client_hash_constant = "Tor safe cookie authentication controller-to-server hash";
    const char* server_hash_constant = "Tor safe cookie authentication server-to-controller hash";

    // read secret from cookiefile
    char* secret = read_cookiefile_secret(protocol_info);
    if(secret == NULL) return false;

    // generate random nonce
    unsigned int client_nonce_size = 32;
    char* client_nonce = rand_bytes(client_nonce_size);
    if(client_nonce == NULL) {
        free(secret);
        perror("[TORC] FAILED TO GENERATE CLIENT NONCE FOR SAFECOOKIE AUTHENTICATION");
        return false;
    }
    char* client_nonce_hex = malloc(client_nonce_size * 2 + 1);
    if(client_nonce_hex == NULL) {
        free(secret);
        free(client_nonce);
        perror("[TORC] FAILED TO GENERATE CLIENT NONCE FOR SAFECOOKIE AUTHENTICATION");
        return false;
    }
    char* p = client_nonce_hex;
    for(int i = 0; i < 32; i++) {
        write_hex(p, client_nonce[i]);
        p += 2;
    }
    *p = 0;

    // send authchallenge
    torc_command command;
    torc_authchallenge_response authchallenge = torc_authchallenge(controller, &command, client_nonce_hex);
    if(!authchallenge.sent || !command.response.ok || authchallenge.server_nonce == NULL || authchallenge.server_hash == NULL) {
        free(secret);
        free(client_nonce);
        free(client_nonce_hex);
        perror("[TORC] FAILED TO SEND AUTHCHALLENGE IN SAFECOOKIE AUTHENTICATION");
        return false;
    }

    // convert server nonce hex to byte array
    size_t server_nonce_size = strlen(authchallenge.server_nonce) / 2;
    char* server_nonce = malloc(server_nonce_size);
    for(int i = 0; i < server_nonce_size; i++) {
        server_nonce[i] = (char) read_double_hex(authchallenge.server_nonce + i * 2);
    }

    // compute hmac
    char* hmac = safecookie_hmac_hex(client_hash_constant, secret, strlen(secret), client_nonce, client_nonce_size, server_nonce, server_nonce_size);

    // compute servers hash and compare
    char* server_hmac = safecookie_hmac_hex(server_hash_constant, secret, strlen(secret), client_nonce, client_nonce_size, server_nonce, server_nonce_size);
    if(strcmp(server_hmac, authchallenge.server_hash) != 0) {
        free(server_hmac);
        free(hmac);
        free(secret);
        free(client_nonce);
        free(client_nonce_hex);
        free(server_nonce);
        perror("[TORC] FAILED TO VERIFY SERVERS AUTHENTICITY USING HMAC HASH");
        return false;
    }
    free(server_hmac);

    // authenticate with hmac
    torc_free_command(&command);
    if(torc_create_command(&command, TORC_AUTHENTICATE, 1) != 0) {
        free(hmac);
        free(secret);
        free(client_nonce);
        free(client_nonce_hex);
        free(server_nonce);
        perror("[TORC] FAILED TO CREATE COMMAND FOR SAFECOOKIE AUTHENTICATION");
        return false;
    }
    if(torc_add_option(&command, hmac) != 0) {
        torc_free_command(&command);
        free(hmac);
        free(secret);
        free(client_nonce);
        free(client_nonce_hex);
        free(server_nonce);
        perror("[TORC] FAILED TO CREATE COMMAND FOR SAFECOOKIE AUTHENTICATION");
        return false;
    }
    if(torc_send_command(controller, &command) != 0) {
        torc_free_command(&command);
        free(hmac);
        free(secret);
        free(client_nonce);
        free(client_nonce_hex);
        free(server_nonce);
        perror("[TORC] FAILED TO SEND COMMAND FOR SAFECOOKIE AUTHENTICATION");
        return false;
    }

    bool authenticated = command.response.ok;
    torc_free_command(&command);
    free(hmac);
    free(server_nonce);
    free(client_nonce);
    free(client_nonce_hex);
    free(secret);
    return authenticated;
}

bool torc_authenticate(torc* controller, char* password) {
    // get protocol info
    torc_command command;
    torc_protocol_info_response protocol_info = torc_get_protocol_info(controller, &command);
    if(!protocol_info.sent || !command.response.ok) {
        torc_free_command(&command);
        perror("[TORC] FAILED TO SEND PROTOCOL INFO COMMAND FOR AUTHENTICATION");
        return false;
    }

    // branch off to other authentication methods
    if(protocol_info.auth_methods == TORC_FLAGS_NONE) {
        return none_authenticate(controller);
    } else if((protocol_info.auth_methods & TORC_FLAGS_SAFECOOKIE) == TORC_FLAGS_SAFECOOKIE) { // SAFECOOKIE should be used whenever possible
        return safe_cookie_authenticate(controller, protocol_info);
    } else if((protocol_info.auth_methods & TORC_FLAGS_COOKIE) == TORC_FLAGS_COOKIE) {
        return cookie_authenticate(controller, protocol_info);
    } else if(password != NULL && (protocol_info.auth_methods & TORC_FLAGS_HASHEDPASSWORD) == TORC_FLAGS_HASHEDPASSWORD) {
        return torc_password_authenticate(controller, password);
    } else if((protocol_info.auth_methods & TORC_FLAGS_COOKIE) == TORC_FLAGS_COOKIE) {
        return cookie_authenticate(controller, protocol_info);
    }

    torc_free_command(&command);
    return false;
}

bool torc_cookie_authenticate(torc* controller) {
    torc_command command;
    torc_protocol_info_response protocol_info = torc_get_protocol_info(controller, &command);
    if(!protocol_info.sent || !command.response.ok) {
        torc_free_command(&command);
        perror("[TORC] FAILED TO SEND PROTOCOL INFO COMMAND FOR AUTHENTICATION");
        return false;
    }
    torc_free_command(&command);
    return cookie_authenticate(controller, protocol_info);
}

bool torc_safe_cookie_authenticate(torc* controller) {
    torc_command command;
    torc_protocol_info_response protocol_info = torc_get_protocol_info(controller, &command);
    if(!protocol_info.sent || !command.response.ok) {
        torc_free_command(&command);
        perror("[TORC] FAILED TO SEND PROTOCOL INFO COMMAND FOR AUTHENTICATION");
        return false;
    }
    torc_free_command(&command);
    return safe_cookie_authenticate(controller, protocol_info);
}

// ERROR CHECK THESE COMMANDS
bool torc_password_authenticate(torc* controller, char* password) {
    // quote password
    char* quoted = dquote(password);
    if(quoted == NULL) {
        perror("[TORC] FAILED TO AUTHENTICATE WITH PASSWORD");
        return false;
    }

    // send command
    torc_command command;
    if(torc_create_command(&command, TORC_AUTHENTICATE, 1) != 0) {
        free(quoted);
        perror("[TORC] FAILED TO CREATE COMMAND FOR PASSWORD AUTHENTICATION");
        return false;
    }
    if(torc_add_option(&command, quoted) != 0) {
        free(quoted);
        torc_free_command(&command);
        perror("[TORC] FAILED TO CREATE COMMAND FOR PASSWORD AUTHENTICATION");
        return false;
    }
    if(torc_send_command(controller, &command) != 0) {
        free(quoted);
        torc_free_command(&command);
        perror("[TORC] FAILED TO SEND COMMAND FOR PASSWORD AUTHENTICATION");
        return false;
    }

    bool authenticated = command.response.ok;
    torc_free_command(&command);
    free(quoted);
    return authenticated;
}

torc_add_onion_response torc_add_new_onion(torc* controller, torc_command* command, char* port, int flags, int auth_num, ...) {
    torc_add_onion_response response = { false };

    // copy client auths(var args) to array
    const char* auth_keys[auth_num];
    va_list args;
    va_start(args, auth_num);
    for(int i = 0; i < auth_num; i++) {
        auth_keys[i] = va_arg(args, char*);
    }
    va_end(args);

    if(torc_create_command(command, TORC_ADD_ONION, (flags != TORC_FLAGS_NONE ? 3 : 2) + auth_num) != 0) {
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
        free(port_target);
        perror("[TORC] FAILED TO ADD PORT OPTION TO ADD NEW ONION COMMAND");
        return response;
    }

    // add client auths
    char* client_auths[auth_num];
    for(int i = 0; i < auth_num; i++) {
        char* auth = concat("ClientAuthV3=", client_auths[i]);
        if(auth == NULL) {
            free(port_target);
            for(int j = 0; j < i; j++) free(client_auths[j]);
            perror("[TORC] FAILED TO ADD PORT OPTION TO ADD NEW ONION COMMAND");
            return response;
        }
        if(torc_add_option(command, auth) != 0) {
            free(port_target);
            for(int j = 0; j < i; j++) free(client_auths[j]);
            perror("[TORC] FAILED TO ADD CLIENT AUTH OPTION TO ADD NEW ONION COMMAND");
            return response;
        }
    }

    // add flags to command
    char* flag_str = NULL;
    if(flags != TORC_FLAGS_NONE) {
        char* flag_list = write_flags(flags, 4, "DiscardPK", "Detach", "V3Auth", "NonAnonymous");
        flag_str = concat("Flags=", flag_list);
        if(flag_str == NULL) {
            free(port_target);
            for(int i = 0; i < auth_num; i++) free(client_auths[i]);
            perror("[TORC] FAILED TO ALLOCATE MEM FOR FLAG OPTION IN ADD NEW ONION COMMAND");
            return response;
        }
        free(flag_list);

        if(torc_add_option(command, flag_str) != 0) {
            free(port_target);
            for(int i = 0; i < auth_num; i++) free(client_auths[i]);
            free(flag_str);
            perror("[TORC] FAILED TO ADD FLAG OPTION TO ADD NEW ONION COMMAND");
            return response;
        }
    }

    // send command
    if(torc_send_command(controller, command) != 0) {
        free(port_target);
        for(int i = 0; i < auth_num; i++) free(client_auths[i]);
        if(flags != TORC_FLAGS_NONE) free(flag_str);
        perror("[TORC] FAILED TO SEND ADD NEW ONION COMMAND");
        return response;
    }
    response.sent = true;
    free(port_target);
    for(int i = 0; i < auth_num; i++) free(client_auths[i]);
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

bool torc_del_onion(torc* controller, torc_command* command, char* service_id) {
    if(torc_create_command(command, TORC_DEL_ONION, 1) != 0) {
        perror("[TORC] FAILED TO CREATE DEL ONION COMMAND");
        return false;
    }
    if(torc_add_option(command, service_id) != 0) {
        perror("[TORC] FAILED TO ADD OPTION TO DEL ONION COMMAND");
        return false;
    }
    if(torc_send_command(controller, command) != 0) {
        perror("[TORC] FAILED TO SEND DEL ONION COMMAND");
        return false;
    }
    return command->response.ok;
}

bool torc_send_signal(torc* controller, torc_command* command, const char* signal) {
    if(torc_create_command(command, TORC_SIGNAL, 1) != 0) {
        perror("[TORC] FAILED TO CREATE SIGNAL COMMAND");
        return false;
    }
    if(torc_add_option(command, (char*) signal) != 0) {
        perror("[TORC] FAILED TO ADD OPTION TO SIGNAL COMMAND");
        return false;
    }
    if(torc_send_command(controller, command) != 0) {
        perror("[TORC] FAILED TO SEND SIGNAL COMMAND");
        return false;
    }
    return command->response.ok;
}

bool torc_take_ownership(torc* controller, torc_command* command) {
    if(torc_create_command(command, TORC_TAKEOWNERSHIP, 0) != 0) {
        perror("[TORC] FAILED TO CREATE TAKEOWNERSHIP COMMAND");
        return false;
    }
    if(torc_send_command(controller, command) != 0) {
        perror("[TORC] FAILED TO SEND TAKEOWNERSHIP COMMAND");
        return false;
    }
    return command->response.ok;
}

bool torc_drop_ownership(torc* controller, torc_command* command) {
    if(torc_create_command(command, TORC_DROPOWNERSHIP, 0) != 0) {
        perror("[TORC] FAILED TO CREATE DROPOWNERSHIP COMMAND");
        return false;
    }
    if(torc_send_command(controller, command) != 0) {
        perror("[TORC] FAILED TO SEND DROPOWNERSHIP COMMAND");
        return false;
    }
    return command->response.ok;
}
