#define _POSIX_C_SOURCE 200809L

#include "libfabric.h"

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connhelpers.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void
print_fi_error(const char *fn, const char *msg, int err)
{
    fprintf(stderr, " ! %s: %s: %s (%d)\n", fn, msg, fi_strerror(-err), -err);
}

int
eq_wait(struct fid_eq *const eq)
{
    int err = 0;

    for (;;) {
        struct fi_eq_entry entry;
        uint32_t event;

        err = fi_eq_read(eq, &event, &entry, sizeof(entry), 0);
        if (err > 0) {
            printf(" * Incoming event: %s\n", fi_tostr(&entry.data, FI_TYPE_EQ_EVENT));
            return 0;
        }

        if (err == -FI_EAVAIL) {
            struct fi_eq_err_entry err_entry;
            const char *err_msg;

            if ((err = fi_eq_readerr(eq, &err_entry, 0))) {
                print_fi_error("eq_wait", "fi_eq_readerr", err);
                goto end;
            }

            err_msg = fi_eq_strerror(eq, err_entry.prov_errno,
                                     err_entry.err_data, 0, 0);
            printf(" * %s %s\n", fi_strerror(err_entry.err), err_msg);

            return err;
        }

        if (err == -FI_EAGAIN)
            continue;

        print_fi_error("eq_wait", "fi_eq_read", err);
        goto end;
    }

end:
    return err;
}

static void
print_cq_msg_entry(struct fi_cq_msg_entry const *const entry)
{
    printf(" * Completion flags: %s\n", fi_tostr(&entry->flags, FI_TYPE_CQ_EVENT_FLAGS));
    if (entry->flags & FI_RECV) {
        printf("   -> Received %ld bytes\n", entry->len);
    }
}

int
cq_wait(struct fid_cq *const cq, struct fi_cq_msg_entry *res)
{
    struct fi_cq_msg_entry dummy;
    int err = 0;

    if (res == 0)
        res = &dummy;

    for (;;) {
        err = fi_cq_read(cq, res, 1);
        if (err > 0) {
            print_cq_msg_entry(res);
            return 0;
        }

        if (err == -FI_EAVAIL) {
            struct fi_cq_err_entry err_entry;
            const char *err_msg;

            if ((err = fi_cq_readerr(cq, &err_entry, 0))) {
                print_fi_error("cq_wait", "fi_cq_readerr", err);
                goto end;
            }

            err_msg = fi_cq_strerror(cq, err_entry.prov_errno,
                                     err_entry.err_data, 0, 0);
            printf(" * %s %s\n", fi_strerror(err_entry.err), err_msg);

            return err;
        }

        if (err == -FI_EAGAIN)
            continue;

        print_fi_error("cq_wait", "fi_cq_read", err);
        goto end;
    }

end:
    return err;
}

int
lookup_sa(struct sockaddr_in *const out, struct fid_av *const av, fi_addr_t addr)
{
    int err;
    size_t buf_len = 128;
    char buf[buf_len];

    if ((err = fi_av_lookup(av, addr, buf, &buf_len))) {
        print_fi_error("lookup_sa", "fi_av_lookup", err);
        return -1;
    }
    if (buf_len != sizeof(struct sockaddr_in))
        return -1;

    memcpy(out, buf, sizeof(struct sockaddr_in));
    return 0;
}

int
repeat_send(struct fid_ep *const e, void *const buf, size_t const len, fi_addr_t to)
{
    int err;

    while ((err = fi_send(e, buf, len, 0, to, 0)) == -FI_EAGAIN)
        print_fi_error("repeat_send", "fi_send", err);

    if (err)
        print_fi_error("repeat_send", "fi_send", err);

    return err;
}

int
state_create(struct state *const s, char const *const port)
{
    int err = 0;
    struct fi_info *hints;
    struct fi_eq_attr eq_attr = {0};
    struct fi_cq_attr cq_attr = {0};
    struct fi_av_attr av_attr = {0};

    printf(" * Starting libfabric\n");

    *s = (struct state) {0};

    eq_attr.size = 64;
    cq_attr.format = FI_CQ_FORMAT_MSG;
    cq_attr.size = 64;
    av_attr.flags = FI_EVENT;
    av_attr.type = FI_AV_TABLE;

    hints = fi_allocinfo();
    if (!hints)
        return -FI_ENOMEM;
    hints->ep_attr->type = FI_EP_DGRAM;
    hints->caps = FI_MSG | FI_SOURCE;
    if ((err = fi_getinfo(FI_VERSION(1, 9), 0, port, port ? FI_SOURCE : 0, hints, &s->fi))) {
        print_fi_error("state_create", "fi_getinfo", err);
        goto end;
    }

    s->root_fi = s->fi;
    for (; s->fi; s->fi = s->fi->next) {
        if (!strncmp(s->fi->fabric_attr->prov_name, "UDP", 3))
            break;
        printf(" * Discarding %s\n", s->fi->fabric_attr->prov_name);
    }
    if (!s->fi) {
        fprintf(stderr, " ! No TCP provider available\n");
        err = -ENOENT;
        goto end;
    }

    printf(" * Choosen fi %s", fi_tostr(s->fi, FI_TYPE_INFO));

    if ((err = fi_fabric(s->fi->fabric_attr, &s->fabric, 0))) {
        print_fi_error("state_create", "fi_fabric", err);
        goto end;
    }
    if ((err = fi_domain(s->fabric, s->fi, &s->domain, 0))) {
        print_fi_error("state_create", "fi_domain", err);
        goto end;
    }
    if ((err = fi_eq_open(s->fabric, &eq_attr, &s->events, 0))) {
        print_fi_error("state_create", "fi_eq_open", err);
        goto end;
    }
    if ((err = fi_cq_open(s->domain, &cq_attr, &s->completions, 0))) {
        print_fi_error("state_create", "fi_cq_open", err);
        goto end;
    }
    if ((err = fi_av_open(s->domain, &av_attr, &s->addresses, 0))) {
        print_fi_error("state_create", "fi_av_open", err);
        goto end;
    }
    if ((err = fi_endpoint(s->domain, s->fi, &s->endpoint, 0))) {
        print_fi_error("state_create", "fi_endpoint", err);
        goto end;
    }
    if ((err = fi_ep_bind(s->endpoint, &s->events->fid, 0))) {
        print_fi_error("state_create", "fi_ep_bind with eq", err);
        goto end;
    }
    if ((err = fi_ep_bind(s->endpoint, &s->completions->fid, FI_TRANSMIT | FI_RECV))) {
        print_fi_error("state_create", "fi_ep_bind with cq", err);
        goto end;
    }
    if ((err = fi_ep_bind(s->endpoint, &s->addresses->fid, 0))) {
        print_fi_error("state_create", "fi_ep_bind with av", err);
        goto end;
    }
    if ((err = fi_av_bind(s->addresses, &s->events->fid, 0))) {
        print_fi_error("state_create", "fi_av_bind", err);
        goto end;
    }
    if ((err = fi_enable(s->endpoint))) {
        print_fi_error("state_create", "fi_enable", err);
        goto end;
    }

    printf(" * Choosen address vector: %s\n", fi_tostr(&av_attr, FI_TYPE_AV_TYPE));

    s->local_addr_len = 0;
    fi_getname(&s->endpoint->fid, 0, &s->local_addr_len);
    s->local_addr = malloc(s->local_addr_len);
    if ((err = fi_getname(&s->endpoint->fid, s->local_addr, &s->local_addr_len))) {
        print_fi_error("state_create", "fi_getname", err);
        goto end;
    }

end:
    if (err)
        state_destroy(s);
    fi_freeinfo(hints);
    return err;
}

void
state_destroy(struct state *const s)
{
    free(s->local_addr);
    if (s->endpoint)
        fi_close(&s->endpoint->fid);
    if (s->completions)
        fi_close(&s->completions->fid);
    if (s->addresses)
        fi_close(&s->addresses->fid);
    if (s->events)
        fi_close(&s->events->fid);
    if (s->domain)
        fi_close(&s->domain->fid);
    if (s->fabric)
        fi_close(&s->fabric->fid);
    if (s->root_fi)
        fi_freeinfo(s->root_fi);
}

static void fabricEventHandler(struct aeEventLoop *el, int fd, void *clientData, int mask) {
    UNUSED(el);
    UNUSED(fd);
    tls_connection *conn = clientData;
    int ret;

    TLSCONN_DEBUG("tlsEventHandler(): fd=%d, state=%d, mask=%d, r=%d, w=%d, flags=%d",
            fd, conn->c.state, mask, conn->c.read_handler != NULL, conn->c.write_handler != NULL,
            conn->flags);

    ERR_clear_error();

    switch (conn->c.state) {
        case CONN_STATE_CONNECTING:
            if (connGetSocketError((connection *) conn)) {
                conn->c.last_errno = errno;
                conn->c.state = CONN_STATE_ERROR;
            } else {
                if (!(conn->flags & TLS_CONN_FLAG_FD_SET)) {
                    SSL_set_fd(conn->ssl, conn->c.fd);
                    conn->flags |= TLS_CONN_FLAG_FD_SET;
                }
                ret = SSL_connect(conn->ssl);
                if (ret <= 0) {
                    WantIOType want = 0;
                    if (!handleSSLReturnCode(conn, ret, &want)) {
                        registerSSLEvent(conn, want);

                        /* Avoid hitting UpdateSSLEvent, which knows nothing
                         * of what SSL_connect() wants and instead looks at our
                         * R/W handlers.
                         */
                        return;
                    }

                    /* If not handled, it's an error */
                    conn->c.state = CONN_STATE_ERROR;
                } else {
                    conn->c.state = CONN_STATE_CONNECTED;
                }
            }

            if (!callHandler((connection *) conn, conn->c.conn_handler)) return;
            conn->c.conn_handler = NULL;
            break;
        case CONN_STATE_ACCEPTING:
            ret = SSL_accept(conn->ssl);
            if (ret <= 0) {
                WantIOType want = 0;
                if (!handleSSLReturnCode(conn, ret, &want)) {
                    /* Avoid hitting UpdateSSLEvent, which knows nothing
                     * of what SSL_connect() wants and instead looks at our
                     * R/W handlers.
                     */
                    registerSSLEvent(conn, want);
                    return;
                }

                /* If not handled, it's an error */
                conn->c.state = CONN_STATE_ERROR;
            } else {
                conn->c.state = CONN_STATE_CONNECTED;
            }

            if (!callHandler((connection *) conn, conn->c.conn_handler)) return;
            conn->c.conn_handler = NULL;
            break;
        case CONN_STATE_CONNECTED:
        {
            int call_read = ((mask & AE_READABLE) && conn->c.read_handler) ||
                ((mask & AE_WRITABLE) && (conn->flags & TLS_CONN_FLAG_READ_WANT_WRITE));
            int call_write = ((mask & AE_WRITABLE) && conn->c.write_handler) ||
                ((mask & AE_READABLE) && (conn->flags & TLS_CONN_FLAG_WRITE_WANT_READ));

            /* Normally we execute the readable event first, and the writable
             * event laster. This is useful as sometimes we may be able
             * to serve the reply of a query immediately after processing the
             * query.
             *
             * However if WRITE_BARRIER is set in the mask, our application is
             * asking us to do the reverse: never fire the writable event
             * after the readable. In such a case, we invert the calls.
             * This is useful when, for instance, we want to do things
             * in the beforeSleep() hook, like fsynching a file to disk,
             * before replying to a client. */
            int invert = conn->c.flags & CONN_FLAG_WRITE_BARRIER;

            if (!invert && call_read) {
                conn->flags &= ~TLS_CONN_FLAG_READ_WANT_WRITE;
                if (!callHandler((connection *) conn, conn->c.read_handler)) return;
            }

            /* Fire the writable event. */
            if (call_write) {
                conn->flags &= ~TLS_CONN_FLAG_WRITE_WANT_READ;
                if (!callHandler((connection *) conn, conn->c.write_handler)) return;
            }

            /* If we have to invert the call, fire the readable event now
             * after the writable one. */
            if (invert && call_read) {
                conn->flags &= ~TLS_CONN_FLAG_READ_WANT_WRITE;
                if (!callHandler((connection *) conn, conn->c.read_handler)) return;
            }

            /* If SSL has pending that, already read from the socket, we're at
             * risk of not calling the read handler again, make sure to add it
             * to a list of pending connection that should be handled anyway. */
            if ((mask & AE_READABLE)) {
                if (SSL_pending(conn->ssl) > 0) {
                    if (!conn->pending_list_node) {
                        listAddNodeTail(pending_list, conn);
                        conn->pending_list_node = listLast(pending_list);
                    }
                } else if (conn->pending_list_node) {
                    listDelNode(pending_list, conn->pending_list_node);
                    conn->pending_list_node = NULL;
                }
            }

            break;
        }
        default:
            break;
    }

    updateSSLEvent(conn);
}

static void connFabricClose(connection *conn_) {
    tls_connection *conn = (tls_connection *) conn_;

    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    if (conn->ssl_error) {
        zfree(conn->ssl_error);
        conn->ssl_error = NULL;
    }

    if (conn->pending_list_node) {
        listDelNode(pending_list, conn->pending_list_node);
        conn->pending_list_node = NULL;
    }

    CT_Socket.close(conn_);
}

static int connFabricAccept(connection *_conn, ConnectionCallbackFunc accept_handler) {
    tls_connection *conn = (tls_connection *) _conn;
    int ret;

    if (conn->c.state != CONN_STATE_ACCEPTING) return C_ERR;
    ERR_clear_error();

    /* Try to accept */
    conn->c.conn_handler = accept_handler;
    ret = SSL_accept(conn->ssl);

    if (ret <= 0) {
        WantIOType want = 0;
        if (!handleSSLReturnCode(conn, ret, &want)) {
            registerSSLEvent(conn, want);   /* We'll fire back */
            return C_OK;
        } else {
            conn->c.state = CONN_STATE_ERROR;
            return C_ERR;
        }
    }

    conn->c.state = CONN_STATE_CONNECTED;
    if (!callHandler((connection *) conn, conn->c.conn_handler)) return C_OK;
    conn->c.conn_handler = NULL;

    return C_OK;
}

static int connFabricConnect(connection *conn_, const char *addr, int port, const char *src_addr, ConnectionCallbackFunc connect_handler) {
    tls_connection *conn = (tls_connection *) conn_;

    if (conn->c.state != CONN_STATE_NONE) return C_ERR;
    ERR_clear_error();

    /* Initiate Socket connection first */
    if (CT_Socket.connect(conn_, addr, port, src_addr, connect_handler) == C_ERR) return C_ERR;

    /* Return now, once the socket is connected we'll initiate
     * TLS connection from the event handler.
     */
    return C_OK;
}

static int connFabricWrite(connection *conn_, const void *data, size_t data_len) {
    tls_connection *conn = (tls_connection *) conn_;
    int ret, ssl_err;

    if (conn->c.state != CONN_STATE_CONNECTED) return -1;
    ERR_clear_error();
    ret = SSL_write(conn->ssl, data, data_len);

    if (ret <= 0) {
        WantIOType want = 0;
        if (!(ssl_err = handleSSLReturnCode(conn, ret, &want))) {
            if (want == WANT_READ) conn->flags |= TLS_CONN_FLAG_WRITE_WANT_READ;
            updateSSLEvent(conn);
            errno = EAGAIN;
            return -1;
        } else {
            if (ssl_err == SSL_ERROR_ZERO_RETURN ||
                    ((ssl_err == SSL_ERROR_SYSCALL && !errno))) {
                conn->c.state = CONN_STATE_CLOSED;
                return 0;
            } else {
                conn->c.state = CONN_STATE_ERROR;
                return -1;
            }
        }
    }

    return ret;
}

static int connFabricRead(connection *conn_, void *buf, size_t buf_len) {
    tls_connection *conn = (tls_connection *) conn_;
    int ret;
    int ssl_err;

    if (conn->c.state != CONN_STATE_CONNECTED) return -1;
    ERR_clear_error();
    ret = SSL_read(conn->ssl, buf, buf_len);
    if (ret <= 0) {
        WantIOType want = 0;
        if (!(ssl_err = handleSSLReturnCode(conn, ret, &want))) {
            if (want == WANT_WRITE) conn->flags |= TLS_CONN_FLAG_READ_WANT_WRITE;
            updateSSLEvent(conn);

            errno = EAGAIN;
            return -1;
        } else {
            if (ssl_err == SSL_ERROR_ZERO_RETURN ||
                    ((ssl_err == SSL_ERROR_SYSCALL) && !errno)) {
                conn->c.state = CONN_STATE_CLOSED;
                return 0;
            } else {
                conn->c.state = CONN_STATE_ERROR;
                return -1;
            }
        }
    }

    return ret;
}

static const char *connFabricGetLastError(connection *conn_) {
    tls_connection *conn = (tls_connection *) conn_;

    if (conn->ssl_error) return conn->ssl_error;
    return NULL;
}

int connFabricSetWriteHandler(connection *conn, ConnectionCallbackFunc func, int barrier) {
    conn->write_handler = func;
    if (barrier)
        conn->flags |= CONN_FLAG_WRITE_BARRIER;
    else
        conn->flags &= ~CONN_FLAG_WRITE_BARRIER;
    updateSSLEvent((tls_connection *) conn);
    return C_OK;
}

int connFabricSetReadHandler(connection *conn, ConnectionCallbackFunc func) {
    conn->read_handler = func;
    updateSSLEvent((tls_connection *) conn);
    return C_OK;
}

static void setBlockingTimeout(tls_connection *conn, long long timeout) {
    anetBlock(NULL, conn->c.fd);
    anetSendTimeout(NULL, conn->c.fd, timeout);
    anetRecvTimeout(NULL, conn->c.fd, timeout);
}

static void unsetBlockingTimeout(tls_connection *conn) {
    anetNonBlock(NULL, conn->c.fd);
    anetSendTimeout(NULL, conn->c.fd, 0);
    anetRecvTimeout(NULL, conn->c.fd, 0);
}

static int connFabricBlockingConnect(connection *conn_, const char *addr, int port, long long timeout) {
    tls_connection *conn = (tls_connection *) conn_;
    int ret;

    if (conn->c.state != CONN_STATE_NONE) return C_ERR;

    /* Initiate socket blocking connect first */
    if (CT_Socket.blocking_connect(conn_, addr, port, timeout) == C_ERR) return C_ERR;

    /* Initiate TLS connection now.  We set up a send/recv timeout on the socket,
     * which means the specified timeout will not be enforced accurately. */
    SSL_set_fd(conn->ssl, conn->c.fd);
    setBlockingTimeout(conn, timeout);

    if ((ret = SSL_connect(conn->ssl)) <= 0) {
        conn->c.state = CONN_STATE_ERROR;
        return C_ERR;
    }
    unsetBlockingTimeout(conn);

    conn->c.state = CONN_STATE_CONNECTED;
    return C_OK;
}

static ssize_t connFabricSyncWrite(connection *conn_, char *ptr, ssize_t size, long long timeout) {
    tls_connection *conn = (tls_connection *) conn_;

    setBlockingTimeout(conn, timeout);
    SSL_clear_mode(conn->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    int ret = SSL_write(conn->ssl, ptr, size);
    SSL_set_mode(conn->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    unsetBlockingTimeout(conn);

    return ret;
}

static ssize_t connFabricSyncRead(connection *conn_, char *ptr, ssize_t size, long long timeout) {
    tls_connection *conn = (tls_connection *) conn_;

    setBlockingTimeout(conn, timeout);
    int ret = SSL_read(conn->ssl, ptr, size);
    unsetBlockingTimeout(conn);

    return ret;
}

static ssize_t connFabricSyncReadLine(connection *conn_, char *ptr, ssize_t size, long long timeout) {
    tls_connection *conn = (tls_connection *) conn_;
    ssize_t nread = 0;

    setBlockingTimeout(conn, timeout);

    size--;
    while(size) {
        char c;

        if (SSL_read(conn->ssl,&c,1) <= 0) {
            nread = -1;
            goto exit;
        }
        if (c == '\n') {
            *ptr = '\0';
            if (nread && *(ptr-1) == '\r') *(ptr-1) = '\0';
            goto exit;
        } else {
            *ptr++ = c;
            *ptr = '\0';
            nread++;
        }
        size--;
    }
exit:
    unsetBlockingTimeout(conn);
    return nread;
}

ConnectionType CT_Fabric = {
    .ae_handler = fabricEventHandler,
    .accept = connFabricAccept,
    .connect = connFabricConnect,
    .blocking_connect = connFabricBlockingConnect,
    .read = connFabricRead,
    .write = connFabricWrite,
    .close = connFabricClose,
    .set_write_handler = connFabricSetWriteHandler,
    .set_read_handler = connFabricSetReadHandler,
    .get_last_error = connFabricGetLastError,
    .sync_write = connFabricSyncWrite,
    .sync_read = connFabricSyncRead,
    .sync_readline = connFabricSyncReadLine,
};
