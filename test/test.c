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
    torc_protocol_info_response protocol_info_response = torc_get_protocol_info(&controller, &command);
    if(protocol_info_response.sent) printf("TOR VERSION: %s\n", protocol_info_response.version);
    else printf("FAILED TO SEND PROTOCOLINFO COMMAND\n");
    torc_free_command(&command);

    // add temporary onion service for webserver
    torc_add_onion_response add_onion_response = torc_add_new_onion(&controller, &command, "80,8000", TORC_FLAGS_DISCARD_PK);
    if(add_onion_response.sent) printf("ONION URL: http://%s.onion/\n\n", add_onion_response.service_id);
    else printf("FAILED TO SEND ADD_ONION COMMAND\n\n");
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
