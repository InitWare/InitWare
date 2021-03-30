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

#include <sys/queue.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "cJSON.h"
#include "hashmap.h"
#include "list.h"
#include "log.h"
#include "rpc.h"

#define log_debug log_error

typedef struct Request Request;
typedef struct Response Response;
typedef struct Invocation Invocation;
typedef struct JSONRPCConnection JSONRPCConnection;

struct Request {
        int id;
        char *method;
        cJSON *params;

        TAILQ_ENTRY(Request) entries;
};

struct Response {
        JSONRPCReply rp;
        int id;

        TAILQ_ENTRY(Response) entries;
};

struct Invocation {
        JSONRPCReplyReceivedCallback cb;
        void *userData;
};

struct JSONRPCConnection {
        /* Its parent JSONRPC object. */
        JSONRPC *jsonrpc;

        /* Request objects pending dispatch. */
        TAILQ_HEAD(requests, Request) requests;

        /* Response objects pending dispatch. */
        TAILQ_HEAD(responses, Response) responses;

        /* Request ID:Invocation objects pending reply. */
        Hashmap *invocations;

        int fd;

        /* Total length that needs to be received for the current message. */
        uint32_t lenMsg;
        /* Number of bytes received so far for the current message. */
        size_t offMsg;
        /* Message buffer. */
        char *msg;

        TAILQ_ENTRY(JSONRPCConnection) entries;
};

struct JSONRPC {
        /* All connections - for a 'client' JSONRPC object, probably just one. */
        TAILQ_HEAD(conns, JSONRPCConnection) conns;
        /* All interfaces provided by this endpoint. String:JSONRPCMethod[]. */
        Hashmap *interfaces;
};

static void request_free(Request *req) {
        if (!req)
                return;
        free(req->method);
        cJSON_Delete(req->params);
        free(req);
}

static void response_free(Response *resp) {
        if (!resp)
                return;
        cJSON_Delete(resp->rp.result);
        free(resp->rp.err.message);
        free(resp);
}

/**
 * Validates then enqueues a received request object, checking for good
 * JSON-RPC, method supported, and good form as required by that method's
 * specification, if it provides one.
 *
 * If the request is badly formed, but carries an ID field, then a reply will
 * be made with the error details; if the ID field is missing or invalid, no
 * reply will be made.
 *
 * If the request is well-formed, then it is enqueued in the pending inbound
 * requests queue.
 *
 * @returns -errno on failure.
 */
static int validate_request(JSONRPCConnection *conn, cJSON *obj) {
        cJSON *oMethod = cJSON_GetObjectItem(obj, "method");
        cJSON *oId = cJSON_GetObjectItem(obj, "id");
        cJSON *oParams = cJSON_DetachItemFromObject(obj, "params");
        Request *req;
        int r = 0;
        int id = 0;
        const char *method;

        if (oId) {
                if (!cJSON_IsNumber(oId)) {
                        log_debug("JSON-RPC: Request has non-numeric ID.\n");
                        r = -EINVAL;
                        goto finish;
                }
                id = cJSON_GetNumberValue(oId);
        }
        if (!oMethod || !cJSON_IsString(oMethod)) {
                log_debug("JSON-RPC: Request (%d) has invalid method field.\n", id);
                r = -EINVAL;
                if (id)
                        jsonrpc_conn_reply_error(
                                conn, id, kJEInvalidRequest, "Request has invalid method field.");
        }

        req = malloc(sizeof *req);
        if (!req) {
                r = -ENOMEM;
                goto finish;
        }

        req->id = id;
        req->method = oMethod->valuestring;
        req->params = oParams;
        oMethod->valuestring = NULL;
        oParams = NULL;

finish:
        cJSON_Delete(oParams);

        if (r >= 0)
                TAILQ_INSERT_TAIL(&conn->requests, req, entries);

        return r;
}

static int validate_response(JSONRPCConnection *conn, cJSON *obj) {
        int r = 0;
        cJSON *oId = cJSON_GetObjectItem(obj, "id");
        cJSON *oErr = cJSON_GetObjectItem(obj, "error");
        cJSON *oRes = cJSON_DetachItemFromObject(obj, "result");
        cJSON *oErrCode;
        cJSON *oErrMsg;
        Response *resp;

        oErr = cJSON_GetObjectItem(obj, "error");

        if (!oId || !cJSON_IsNumber(oId)) {
                log_debug("JSON-RPC: Response has bad ID field.\n");
                r = -EINVAL;
                goto finish;
        } else if (oErr) {
                oErrCode = cJSON_GetObjectItem(oErr, "code");
                oErrMsg = cJSON_GetObjectItem(oErr, "message");
                if (!(oErrCode && oErrMsg)) {
                        log_debug("JSON-RPC: Response has bad error field.\n");
                        r = -EINVAL;
                        goto finish;
                }
        } else if (!oRes) {
                log_debug("JSON-RPC: Response has no result or error field.\n");
                r = -EINVAL;
                goto finish;
        }

        resp = malloc(sizeof *resp);
        if (!resp) {
                r = -ENOMEM;
                goto finish;
        }
        resp->id = cJSON_GetNumberValue(oId);
        if (oErr) {
                resp->rp.err.code = (int) cJSON_GetNumberValue(oErrCode);
                resp->rp.err.message = oErrMsg->valuestring;
        } else {
                resp->rp.err.code = 0;
                resp->rp.err.message = NULL;
        }
        resp->rp.result = oRes;
        oErr = NULL;
        oRes = NULL;

finish:
        cJSON_Delete(oRes);

        if (r >= 0)
                TAILQ_INSERT_TAIL(&conn->responses, resp, entries);

        return r;
}

JSONRPC *jsonrpc_new() {
        JSONRPC *rpc = malloc(sizeof *rpc);
        if (!rpc)
                return NULL;
        TAILQ_INIT(&rpc->conns);
        rpc->interfaces = hashmap_new(string_hash_func, string_compare_func);
        if (!rpc->interfaces) {
                free(rpc);
                return NULL;
        }
        return rpc;
}

void jsonrpc_free(JSONRPC *rpc, int closeFDs) {
        while (!TAILQ_EMPTY(&rpc->conns)) {
                JSONRPCConnection *conn = TAILQ_FIRST(&rpc->conns);
                TAILQ_REMOVE(&rpc->conns, conn, entries);
                jsonrpc_conn_free(conn, closeFDs);
        }
        hashmap_free(rpc->interfaces);
        free(rpc);
}

int jsonrpc_add_interface(JSONRPC *jsonrpc, JSONRPCInterface *intf) {
        return hashmap_put(jsonrpc->interfaces, intf->name, (void *) intf->methods);
}

JSONRPCConnection *jsonrpc_conn_new(JSONRPC *rpc, int fd) {
        JSONRPCConnection *conn = malloc(sizeof *conn);

        if (!conn)
                return NULL;

        conn->invocations = hashmap_new(trivial_hash_func, trivial_compare_func);
        if (!conn->invocations) {
                free(conn);
                return NULL;
        }

        TAILQ_INSERT_TAIL(&rpc->conns, conn, entries);

        TAILQ_INIT(&conn->requests);
        TAILQ_INIT(&conn->responses);
        conn->jsonrpc = rpc;
        conn->fd = fd;
        conn->lenMsg = 0;
        conn->offMsg = 0;
        conn->msg = NULL;

        return conn;
}

void jsonrpc_conn_free(JSONRPCConnection *conn, bool closeFD) {
        free(conn->msg);
        while (!TAILQ_EMPTY(&conn->requests)) {
                Request *resp = TAILQ_FIRST(&conn->requests);
                TAILQ_REMOVE(&conn->requests, resp, entries);
                request_free(resp);
        }
        while (!TAILQ_EMPTY(&conn->responses)) {
                Response *resp = TAILQ_FIRST(&conn->responses);
                TAILQ_REMOVE(&conn->responses, resp, entries);
                response_free(resp);
        }
        hashmap_free_free(conn->invocations);
        if (closeFD)
                close(conn->fd);
        free(conn);
}

int jsonrpc_conn_receive(JSONRPCConnection *conn) {
        size_t lenRemaining;

        if (!conn->lenMsg) {
                int len = recv(conn->fd, (char *) &conn->lenMsg, sizeof(uint32_t), 0);
                if (len == -1) {
                        log_error("JSON-RPC: Error receiving: %m\n");
                }
                if (len != 4) {
                        log_debug("JSON-RPC: Invalid message (bad length marker: length %d)\n", len);
                        return -EINVAL;
                }
                conn->msg = (char *) malloc(conn->lenMsg);
                if (!conn->msg) {
                        return log_oom();
                        /* TODO: close connection or just dispose of read buffer until ready?
                         * try to reply with OOM details? */
                        conn->offMsg = 0;
                        conn->lenMsg = 0;
                }
        }

        lenRemaining = conn->lenMsg - conn->offMsg;
        conn->offMsg += recv(conn->fd, conn->msg, lenRemaining, 0);

        if (conn->lenMsg && (conn->offMsg == conn->lenMsg)) {

                /* message fully received */
                int r;
                cJSON *obj = cJSON_ParseWithLength(conn->msg, conn->lenMsg);
                const cJSON *errObj;

                if (!obj) {
                        log_debug("JSON-RPC: Parsing error at:\n%s\n", cJSON_GetErrorPtr());
                        r = -EINVAL;
                        goto finish;
                }

                if (!cJSON_GetObjectItem(obj, "jsonrpc")) {
                        log_debug("JSON-RPC: Message missing jsonrpc field.\n");
                        r = -EINVAL;
                        goto finish;
                }

                if (cJSON_GetObjectItem(obj, "result") || (errObj = cJSON_GetObjectItem(obj, "error"))) {
                        /* it's a response object */
                        r = validate_response(conn, obj);
                        if (r < 0)
                                goto finish;
                } else {
                        r = validate_request(conn, obj);
                        if (r < 0)
                                goto finish;
                }

        finish:
                cJSON_Delete(obj);
                free(conn->msg);

                conn->msg = NULL;
                conn->offMsg = 0;
                conn->lenMsg = 0;

                return r;
        }

        return 0;
}

int jsonrpc_conn_dispatch(JSONRPCConnection *conn) {
        while (!TAILQ_EMPTY(&conn->requests)) {
                Request *req = TAILQ_FIRST(&conn->requests);
                Iterator i;
                JSONRPCMethod *intf_meths;
                bool found = false;

                TAILQ_REMOVE(&conn->requests, req, entries);

                HASHMAP_FOREACH (intf_meths, conn->jsonrpc->interfaces, i) {
                        const JSONRPCMethod *meth = intf_meths;
                        do {
                                if (!strcmp(meth->name, req->method)) {
                                        meth->impl(conn, /* USERDATA */ NULL, req->id, req->params);
                                        found = true;
                                        break;
                                }

                        } while (!found && (++meth)->name != NULL);
                }

                if (!found) {
                        log_debug("JSON-RPC: Unhandled method %s\n", req->method);
                        jsonrpc_conn_reply_error(conn, req->id, kJEMethodNotFound, "Method not found.");
                }

                request_free(req);
        }
        while (!TAILQ_EMPTY(&conn->responses)) {
                Response *resp = TAILQ_FIRST(&conn->responses);
                Invocation *inv;

                TAILQ_REMOVE(&conn->responses, resp, entries);
                inv = hashmap_remove(conn->invocations, INT_TO_PTR(resp->id));

                if (!inv)
                        log_debug("JSON-RPC: Response ID %d does not have an invocation object\n", resp->id);
                else
                        inv->cb(conn, inv->userData, &resp->rp);


                response_free(resp);
                free(inv);
        }

        return 0;
}

/*
 * sending
 */

/* Just sends a cJSON object. */
static int send_obj(JSONRPCConnection *conn, const cJSON *obj) {
        int r = 0;
        char *txt;
        uint32_t len;

        txt = cJSON_Print(obj);
        len = strlen(txt);

        if (write(conn->fd, (char *) &len, sizeof(uint32_t)) < 0) {
                log_error("JSON-RPC: Failed to write length: %m\n");
                r = -errno;
        } else if (write(conn->fd, txt, len) < 0) {
                log_error("JSON-RPC: Failed to write text: %m\n");
                r = -errno;
        }

        free(txt);

        return r;
}

/* Sends a JSON object and frees it. */
static int send_obj_and_free(JSONRPCConnection *conn, cJSON *obj) {
        int r = send_obj(conn, obj);
        cJSON_Delete(obj);
        return r;
}

/*
 * Create a JSON response object.
 *
 * n.b. \p result or \p error are only held as references; they must be
 * separately freed.
 */
static cJSON *make_response(int id, cJSON *result, cJSON *error) {
        cJSON *res = cJSON_CreateObject();

        if (!res)
                return NULL;
        if (!cJSON_AddStringToObject(res, "jsonrpc", "2.0"))
                goto nomem;
        if (!cJSON_AddNumberToObject(res, "id", id))
                goto nomem;
        if (result) {
                if (!cJSON_AddItemReferenceToObject(res, "result", result))
                        goto nomem;
        } else if (error)
                if (!cJSON_AddItemReferenceToObject(res, "error", error))
                        goto nomem;

        return res;

nomem:
        cJSON_Delete(res);
        return NULL;
}

/* Create a JSON request object. */
static cJSON *make_request(int id, const char *method, cJSON *params) {
        cJSON *res = cJSON_CreateObject();

        if (!res)
                return NULL;
        if (!cJSON_AddStringToObject(res, "jsonrpc", "2.0"))
                goto nomem;
        if (!cJSON_AddNumberToObject(res, "id", id))
                goto nomem;
        if (!cJSON_AddStringToObject(res, "method", method))
                goto nomem;
        if (params)
                if (!cJSON_AddItemReferenceToObject(res, "params", params))
                        goto nomem;

        return res;

nomem:
        cJSON_Delete(res);
        return NULL;
}

int jsonrpc_conn_reply_error(JSONRPCConnection *conn, int id, int errNum, const char *msg) {
        cJSON *err = cJSON_CreateObject();
        cJSON *resp;
        int r;

        if (!err)
                return -ENOMEM;

        if (!cJSON_AddNumberToObject(err, "code", errNum)) {
                r = -ENOMEM;
                goto finish;
        }

        if (!cJSON_AddStringToObject(err, "message", msg)) {
                r = -ENOMEM;
                goto finish;
        }

        resp = make_response(id, NULL, err);

        if (!resp) {
                r = -ENOMEM;
                goto finish;
        }

        r = send_obj(conn, resp);

finish:
        cJSON_Delete(resp);
        cJSON_Delete(err);
        return r;
}

int jsonrpc_conn_reply(JSONRPCConnection *conn, int id, cJSON *result) {
        cJSON *resp;
        int r;

        resp = make_response(id, result, NULL);

        if (!resp)
                return -ENOMEM;

        r = send_obj_and_free(conn, resp);

        return r;
}

/* Sends the given message. */
static int conn_send_common(JSONRPCConnection *conn, const char *method, cJSON *params) {
        int id = abs(rand());
        int r;
        cJSON *req = make_request(id, method, params);

        if (!req) {
                return -ENOMEM;
        }

        r = send_obj_and_free(conn, req);

        if (r < 0)
                return r;
        else
                return id;
}

int jsonrpc_conn_send(
        JSONRPCConnection *conn,
        JSONRPCReplyReceivedCallback cb,
        void *userData,
        const char *method,
        cJSON *params) {
        Invocation *inv = malloc(sizeof *inv);
        int r;

        if (!inv)
                return -ENOMEM;

        inv->cb = cb;
        inv->userData = userData;
        r = conn_send_common(conn, method, params);

        if (r < 0)
                free(inv);
        else if (!hashmap_put(conn->invocations, INT_TO_PTR(r), inv))
                log_oom(); /* FIXME */

finish:
        return r;
}
