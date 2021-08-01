#include <sys/socket.h>
#include <sys/un.h>

#include <assert.h>
#include <stdio.h>

#include "rpc.h"

void line1(JSONRPCConnection *conn, void *userData, int id, const cJSON *params) {
        cJSON *reply = cJSON_CreateString("Kublai Khan");
        printf("%s", cJSON_GetStringValue(cJSON_GetArrayItem(params, 0)));
        jsonrpc_conn_reply(conn, id, reply);
        cJSON_Delete(reply);
}

void line2(JSONRPCConnection *conn, void *userData, int id, const cJSON *params) {
        cJSON *reply = cJSON_CreateString("decree");
        printf("%s", cJSON_GetStringValue(cJSON_GetArrayItem(params, 1)));
        jsonrpc_conn_reply(conn, id, reply);
        cJSON_Delete(reply);
}

void replyCb(JSONRPCConnection *conn, void *userData, JSONRPCReply *rp) {
        printf("%s%s", rp->result->valuestring, userData);
}

JSONRPCMethod intf1m[] = { { "line1", line1 }, { "line2", line2 }, { NULL, NULL } };
JSONRPCInterface intf1 = { "com.initware.TestInterface1", intf1m };

const char *strings[2] = { "In Xanadu did ", "A stately Pleasure-Dome " };

int main() {
        JSONRPC *rpc = jsonrpc_new();
        JSONRPCConnection *conn1;
        JSONRPCConnection *conn2;
        cJSON *params;
        int sock[2];

        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sock) >= 0);

        assert(jsonrpc_add_interface(rpc, &intf1) >= 0);
        assert(conn1 = jsonrpc_conn_new(rpc, sock[0]));
        assert(conn2 = jsonrpc_conn_new(rpc, sock[1]));

        params = cJSON_CreateStringArray(strings, 2);

        jsonrpc_conn_send(conn2, replyCb, "\n", "line1", params);

        jsonrpc_conn_receive(conn1);
        jsonrpc_conn_dispatch(conn1);

        jsonrpc_conn_receive(conn2);
        jsonrpc_conn_dispatch(conn2);

        jsonrpc_conn_send(conn2, replyCb, "\n", "line2", params);

        jsonrpc_conn_receive(conn1);
        jsonrpc_conn_dispatch(conn1);

        jsonrpc_conn_receive(conn2);
        jsonrpc_conn_dispatch(conn2);

        cJSON_Delete(params);
        jsonrpc_free(rpc, true);
}
