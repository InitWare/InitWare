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

typedef struct IWRPC IWRPC;
typedef struct IWRPCConnection IWRPCConnection;

enum JSONRPCError {
        kJEParseError = -32700,
        kJEInvalidRequest = -32600,
        kJEMethodNotFound = -32601,
        kJEInvalidParams = -32602,
        kJEInternalError = -32603,
};

IWRPC *iwrpc_new();

/** Call when FD becomes ready for read. */
int iwrpc_conn_receive(IWRPCConnection *conn);