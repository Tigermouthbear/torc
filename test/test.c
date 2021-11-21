#include "../src/torc.h"
#include "mongoose.h"

static int s_signo;
static void signal_handler(int signo) {
    s_signo = signo;
}

static void routing(struct mg_connection *c, int event, void *ev_data, void *fn_data) {
    if(event == MG_EV_HTTP_MSG) {
        mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "hello tor!");
    }
    (void) fn_data;
}

int main() {
    // create tor controller
    torc_info controller_info = { 9051 };
    torc controller;
    if(torc_connect_debug_controller(&controller, controller_info) != 0) {
        printf("FAILED TO CONNECT TOR CONTROLLER!");
        return 1;
    }
    printf("TORC controller connected\n\n");

    // controller authentication
    torc_command command;
    torc_create_command(&command, TORC_AUTHENTICATE, 0);
    torc_send_command(&controller, &command);
    torc_free_command(&command);

    // check controller connection
    torc_create_command(&command, TORC_PROTOCOLINFO, 0);
    torc_send_command(&controller, &command);
    torc_free_command(&command);

    // try to add onion service for webserver
    // the onion url is the ServiceID response + .onion
    torc_create_command(&command, TORC_ADD_ONION, 2);
    torc_add_option(&command, "NEW:BEST");
    torc_add_option(&command, "PORT=80,8000");
    torc_send_command(&controller, &command);
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
