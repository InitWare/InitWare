/*******************************************************************

        LICENCE NOTICE

These coded instructions, statements, and computer programs are part
of the  InitWare Suite of Middleware,  and  they are protected under
copyright law. They may not be distributed,  copied,  or used except
under the provisions of  the  terms  of  the  Library General Public
Licence version 2.1 or later, in the file "LICENSE.md", which should
have been included with this software

        Copyright Notice

    (c) 2021 David Mackay
        All rights reserved.

*********************************************************************/
/**
 * This module provides a simple JSON RPC over stream sockets in the UNIX
 * domain, using cJSON.
 *
 * A discrete message consists of:
 * - 4 bytes, a uint32_t, which denotes the length L of the message.
 * - L bytes of ASCII or UTF-8 text, the message body proper.
 *
 * A server and a client can both provide methods for invocation.
 */

#include <stdbool.h>

#include "cJSON.h"

typedef enum JSONRPCErrorCode JSONRPCErrorCode;
typedef struct JSONRPC JSONRPC;
typedef struct JSONRPCConnection JSONRPCConnection;
typedef struct JSONRPCError JSONRPCError;
typedef struct JSONRPCMethod JSONRPCMethod;
typedef struct JSONRPCInterface JSONRPCInterface;
typedef struct JSONRPCReply JSONRPCReply;

enum JSONRPCErrorCode {
        kJEParseError = -32700,
        kJEInvalidRequest = -32600,
        kJEMethodNotFound = -32601,
        kJEInvalidParams = -32602,
        kJEInternalError = -32603,
};

struct JSONRPCError {
        JSONRPCErrorCode code;
        char *message;
};

/*
 * A function invoked to run a JSON-RPC method.
 */
typedef void (*JSONRPCMethodImpl)(JSONRPCConnection *conn, void *userData, int id, const cJSON *params);

struct JSONRPCMethod {
        const char *name;
        JSONRPCMethodImpl impl;
};

/*
 * A JSON-RPC interface. Statically define one with all methods you wish to use,
 * and add them to JSONRPC objects to expose that interface.
 */
struct JSONRPCInterface {
        const char *name;
        /* The final member of the methods array should have name = NULL. */
        const JSONRPCMethod *methods;
};

/*
 * A JSON-RPC call reply.
 */
struct JSONRPCReply {
        JSONRPCError err;
        cJSON *result;
};

/**
 * The type of a callback invoked when a reply is received to an
 * asynchronously-sent JSON-RPC message.
 *
 * Either \v error or \v result are set in \p rp, not both.
 */
typedef void (*JSONRPCReplyReceivedCallback)(JSONRPCConnection *conn, void *userData, JSONRPCReply *rp);

/* Create a new JSONRPC endpoint. */
JSONRPC *jsonrpc_new();

/* Free a JSONRPC endpoint and all its connections, optionally closing their FDs. */
void jsonrpc_free(JSONRPC *rpc, int closeFDs);

/** Add an interface to a JSONRPC endpoint. Returns 0 if OK, -ENOMEM if not. */
int jsonrpc_add_interface(JSONRPC *jsonrpc, JSONRPCInterface *intf);

/** Create a new JSONRPC connection. */
JSONRPCConnection *jsonrpc_conn_new(JSONRPC *rpc, int fd);

/** Free a JSONRPC connection, optionally closing its FD. */
void jsonrpc_conn_free(JSONRPCConnection *conn, bool closeFD);

/** To call when FD becomes ready for read. */
int jsonrpc_conn_receive(JSONRPCConnection *conn);

/** TO call to dispatch all pending events for a connection after it received. */
int jsonrpc_conn_dispatch(JSONRPCConnection *conn);

/**
 * Send a message. \p callback will be invoked on receipt of a reply.
 *
 * @returns >0 Call ID if message sent.
 * @returns -errno if message could not be sent.
 */
int jsonrpc_conn_send(
        JSONRPCConnection *conn,
        JSONRPCReplyReceivedCallback cb,
        void *userData,
        const char *method,
        cJSON *params);

/**
 * Sends a message and waits up to \p timeout milliseconds for a reply.
 *
 * @returns 0 if message sent and reply (error or result) received.
 * @returns -errno if message could not be sent, no reply was received, or
 * receiving reply failed.
 */
int jsonrpc_conn_sendsynch(
        JSONRPCConnection *conn,
        const char *method,
        cJSON *params,
        int msecTimeout,
        JSONRPCError *error,
        cJSON *result);

/** Send a reply with an error. */
int jsonrpc_conn_reply_error(JSONRPCConnection *conn, int id, int errNum, const char *msg);

/** Send a reply with a result. */
int jsonrpc_conn_reply(JSONRPCConnection *conn, int id, cJSON *result);