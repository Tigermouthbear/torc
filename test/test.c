#include "../src/torc.h"
#include "../src/torcmds.h"
#include "mongoose.h"

static int s_signo;
static void signal_handler(int signo) {
    s_signo = signo;
}

static int inc = 1;
static void routing(struct mg_connection *c, int event, void *ev_data, void *fn_data) {
    if(event == MG_EV_HTTP_MSG) {
        char buf[26];
        snprintf(buf, 26, "hello tor visitor %d!", inc++);
        mg_http_reply(c, 200, "Content-Type: text/plain\r\n", buf);
    }
    (void) fn_data;
}

int main() {
    // create tor controller
    torc controller;
    if(torc_connect_controller(&controller, torc_default_addr_info()) != 0) {
        printf("FAILED TO CONNECT TOR CONTROLLER!");
        return 1;
    }
    //controller.debug = true;
    printf("TORC controller connected\n");

    // authenticate controller
    if(!torc_password_authenticate(&controller, "my_password")) {
        printf("FAILED TO AUTHENTICATE TOR CONTROLLER!");
        torc_close_controller(&controller);
        return 1;
    }
    printf("TORC controller authenticated\n\n");

    // check controller connection
    torc_command command;
    torc_protocol_info_response protocol_info_response = torc_send_protocol_info_command(&controller, &command);
    printf("TOR VERSION: %s\n", protocol_info_response.version);
    torc_free_command(&command);

    // try to add onion service for webserver
    // the onion url is the ServiceID response + .onion
    torc_create_command(&command, TORC_ADD_ONION, 2);
    torc_add_option(&command, "NEW:BEST");
    torc_add_option(&command, "PORT=80,8000");
    torc_send_command(&controller, &command);

    // add_onion command wrapper not added yet... thisll work for now
    torc_key_value* key_value = torc_get_key_value_from_line(&command.response, 0);
    printf("ONION URL: http://%s.onion/\n\n", key_value->value);

    torc_free_command(&command);

    // setup mongoose to listen on addr
    const char* addr = "http://localhost:8000";
    struct mg_mgr mgr;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    mg_mgr_init(&mgr);
    if(mg_http_listen(&mgr, addr, routing, &mgr) == NULL) {
        LOG(LL_ERROR, ("Cannot listen on %s. Use http://ADDR:PORT or :PORT", addr));
    } else {
        // start mongoose event loop
        while(s_signo == 0) mg_mgr_poll(&mgr, 1000);
        mg_mgr_free(&mgr);
    }

    // destroy tor controller
    torc_close_controller(&controller);
    printf("\nTORC controller closed\n");

    return 0;
}
