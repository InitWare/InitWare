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
#include "list.h"
#include "log.h"
#include "rpc.h"

typedef struct Request Request;
typedef struct Response Response;
typedef struct IWRPCConnection IWRPCConnection;

struct Request {
        int id;
        char *method;
        cJSON *params;

        TAILQ_ENTRY(Request) entries;
};

struct Response {
        int id;
        cJSON *error;
        cJSON *result;

        TAILQ_ENTRY(Response) entries;
};

struct IWRPCConnection {
        /* Its parent IWRPC object. */
        IWRPC *iwrpc;

        /* Request objects pending dispatch. */
        TAILQ_HEAD(requests, Request) requests;

        /* Response objects pending dispatch. */
        TAILQ_HEAD(responses, Response) responses;

        int fd;

        /* Total length that needs to be received for the current message. */
        uint32_t lenMsg;
        /* Number of bytes received so far for the current message. */
        size_t offMsg;
        /* Message buffer. */
        char *msg;

        TAILQ_ENTRY(IWRPCConnection) entries;
};

struct IWRPC {
        /* All connections - for a 'client' IWRPC object, probably just one. */
        TAILQ_HEAD(conns, IWRPCConnection) conns;
};

/* Just sends a cJSON object. */
static int send_obj(IWRPCConnection *conn, const cJSON *obj) {
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
static int send_obj_and_free(IWRPCConnection *conn, cJSON *obj) {
        int r = send_obj(conn, obj);
        cJSON_Delete(obj);
        return r;
}

/* Create a response object */
static cJSON *make_response(int id, cJSON *result, cJSON *error) {
        cJSON *res = cJSON_CreateObject();

        cJSON_AddNumberToObject(res, "id", id);
        if (result)
                cJSON_AddItemToObject(res, "result", result);
        else if (error)
                cJSON_AddItemToObject(res, "error", error);

        return res;
}

static int send_error(IWRPCConnection *conn, int id, int errNum, const char *msg) {
        cJSON *err = cJSON_CreateObject();
        cJSON *resp;

        cJSON_AddNumberToObject(err, "code", errNum);
        cJSON_AddStringToObject(err, "message", msg);
        resp = make_response(id, NULL, err);

        return send_obj_and_free(conn, resp);
}

/**
 * Validates a request object, checking for good JSON-RPC, method supported, and
 * good form as required by that method's specification, if it provides one.
 *
 * If the response is badly formed, but carries an ID field, then a reply will
 * be made with the error details.
 *
 * @returns -errno on failure.
 */
static int validate_request(IWRPCConnection *conn, cJSON *obj) {
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
                        send_error(conn, id, kJEInvalidRequest, "Request has invalid method field.");
        }

        req = malloc(sizeof *req);
        if (!req) {
                r = -ENOMEM;
                goto finish;
        }
        req->id = id;
        req->method = oMethod->string;
        req->params = oParams;
        oMethod->string = NULL;
        oParams = NULL;

finish:
        cJSON_Delete(oParams);

        if (r >= 0)
                TAILQ_INSERT_TAIL(&conn->requests, req, entries);

        return r;
}

static int validate_response(IWRPCConnection *conn, cJSON *obj) {
        int r = 0;
        cJSON *oId = cJSON_GetObjectItem(obj, "id");
        cJSON *oErr = cJSON_DetachItemFromObject(obj, "error");
        cJSON *oRes = cJSON_DetachItemFromObject(obj, "result");
        Response *resp;

        oErr = cJSON_GetObjectItem(obj, "error");

        if (!oId || !cJSON_IsNumber(oId)) {
                log_debug("JSON-RPC: Response has bad ID field.\n");
                r = -EINVAL;
                goto finish;
        } else if (oErr) {
                if (!(cJSON_GetObjectItem(oErr, "code") && cJSON_GetObjectItem(oErr, "message"))) {
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
        resp->error = oErr;
        resp->result = oRes;
        oErr = NULL;
        oRes = NULL;

finish:
        cJSON_Delete(oErr);
        cJSON_Delete(oRes);

        return r;
}

int iwrpc_conn_receive(IWRPCConnection *conn) {
        size_t lenRemaining;

        if (!conn->lenMsg) {
                int len = recv(conn->fd, (char *) &conn->lenMsg, sizeof(uint32_t), 0);
                if (len != 4) {
                        log_debug("JSON-RPC: Invalid message (bad length marker)\n");
                        return -EINVAL;
                }
                conn->msg = (char *) malloc(conn->lenMsg);
                if (!conn->msg)
                        return log_oom();
                /* TODO: close connection or just dispose of read buffer until ready?
                 * try to reply with OOM details? */
                conn->offMsg = 0;
                conn->lenMsg = 0;
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