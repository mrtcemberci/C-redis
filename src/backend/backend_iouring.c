#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <liburing.h>
#include <sys/poll.h>

#include "io_backend.h"

#define MAX_FDS       4096
// Match URING_ENTRIES to MAX_FDS to prevent ring overflows during massive bursts
#define URING_ENTRIES 4096 
#define READ_BUF_INIT 4096

// --- Compatibility Defines for Older liburing headers ---
#ifndef IORING_SETUP_SINGLE_ISSUER
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#endif
#ifndef IORING_SETUP_DEFER_TASKRUN
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#endif
#ifndef IORING_SETUP_COOP_TASKRUN
#define IORING_SETUP_COOP_TASKRUN (1U << 14)
#endif

struct io_uring g_ring;
int g_files_registered = 0; 
int g_sqpoll_enabled = 0;

/* Per-FD state */

typedef enum {
    FD_TYPE_NONE = 0,
    FD_TYPE_LISTENER,
    FD_TYPE_CLIENT
} FdType;

typedef struct {
    FdType   type;
    int      active;
    uint32_t interests;
    void* user_data;

    char* read_buf;
    size_t   read_cap;
    size_t   read_len;

    char* write_buf;
    size_t   write_len;
    ssize_t  last_write_res;
} FdState;

static FdState g_fds[MAX_FDS];

/* Tag encoding:
 * lower 2 bits = op:
 * 0 = poll, 1 = accept, 2 = read, 3 = write
 * upper bits = fd
 */

static inline intptr_t make_tag(int fd, int op) {
    return ((intptr_t)fd << 2) | (op & 0x3);
}

static inline void decode_tag(intptr_t tag, int* fd, int* op) {
    *fd = (int)(tag >> 2);
    *op = (int)(tag & 0x3);
}

static void fdstate_reset(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return;
    FdState* st = &g_fds[fd];
    if (st->read_buf) free(st->read_buf);
    memset(st, 0, sizeof(*st));
    st->type = FD_TYPE_NONE;
}

static int      backend_init(void);
static int      backend_make_nonblocking(int fd);
static int      backend_socket_create_listener(int port);
static int      backend_socket_accept(int listener_fd, char* ip_buf, size_t ip_buf_len);
static void     backend_socket_close(int fd);
static int      backend_watch_add(int fd, int events, void* user_data);
static int      backend_watch_mod(int fd, int events, void* user_data);
static int      backend_watch_del(int fd);
static int      backend_poll(IOEvent* events, int max_events, int timeout_ms);
static ssize_t  backend_read(int fd, void* buf, size_t count);
static ssize_t  backend_write(int fd, const void* buf, size_t count);

static int      backend_get_read_buffer(int fd, BackendBuffer* buf);
static int      backend_re_arm_read(int fd);
static ssize_t  backend_submit_write(int fd, const void* buf, size_t count);


/* Asks the kernel to notify us when this fd is ready to read/write */
static void submit_poll_request(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return;
    FdState* st = &g_fds[fd];
    if (!st->active) return;

    struct io_uring_sqe* sqe = io_uring_get_sqe(&g_ring);
    if (!sqe) return;

    short mask = 0;
    if (st->interests & IO_EVENT_READ)  mask |= POLLIN;
    if (st->interests & IO_EVENT_WRITE) mask |= POLLOUT;

    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, (void*)make_tag(fd, 0));

    if (g_files_registered) {
        sqe->flags |= IOSQE_FIXED_FILE;
    }
}

/* Async accept op, used for new connection */
static int submit_accept_request(int listener_fd) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&g_ring);
    if (!sqe) return -1;

    io_uring_prep_accept(sqe, listener_fd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, (void*)make_tag(listener_fd, 1));

    if (g_files_registered) {
        sqe->flags |= IOSQE_FIXED_FILE;
    }
    return 0;
}

/* Prepare an async read, tells the kernel to read data into the st->read_buf */
static int submit_read_request(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return -1;
    FdState* st = &g_fds[fd];
    if (!st->active || st->type != FD_TYPE_CLIENT) return -1;

    if (!st->read_buf || st->read_cap == 0) {
        st->read_cap = READ_BUF_INIT;
        st->read_buf = malloc(st->read_cap);
        if (!st->read_buf) {
            perror("malloc read_buf");
            st->read_cap = 0;
            return -1;
        }
    }

    struct io_uring_sqe* sqe = io_uring_get_sqe(&g_ring);
    if (!sqe) return -1;

    io_uring_prep_read(sqe, fd, st->read_buf, st->read_cap, 0);
    io_uring_sqe_set_data(sqe, (void*)make_tag(fd, 2));

    if (g_files_registered) {
        sqe->flags |= IOSQE_FIXED_FILE;
    }
    return 0;
}

/* Submits a write request, tells kernel to send data from the write_buf */
static int submit_write_request(int fd, const void* buf, size_t count) {
    if (fd < 0 || fd >= MAX_FDS) return -1;
    FdState* st = &g_fds[fd];
    if (!st->active || st->type != FD_TYPE_CLIENT) return -1;

    st->write_buf      = (char*)buf;
    st->write_len      = count;
    st->last_write_res = 0;

    struct io_uring_sqe* sqe = io_uring_get_sqe(&g_ring);
    if (!sqe) return -1;

    io_uring_prep_write(sqe, fd, st->write_buf, st->write_len, 0);
    io_uring_sqe_set_data(sqe, (void*)make_tag(fd, 3));

    if (g_files_registered) {
        sqe->flags |= IOSQE_FIXED_FILE;
    }
    return 0;
}

/* Backend core */

static int backend_init(void) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    int ret = -1;

    /* Optimisation flags */
    params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_DEFER_TASKRUN;
    params.sq_thread_idle = 2000;
    
    ret = io_uring_queue_init_params(URING_ENTRIES, &g_ring, &params);
    
    if (ret == 0) {
        g_sqpoll_enabled = 1;
        printf("(Network) io_uring created in GOD MODE (SQPOLL + SingleIssuer + DeferTaskRun)\n");
    } else {
        /* Top-level optimisation failed, trying next level */
        memset(&params, 0, sizeof(params));
        params.flags = IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 2000;
        
        ret = io_uring_queue_init_params(URING_ENTRIES, &g_ring, &params);
        if (ret == 0) {
            g_sqpoll_enabled = 1;
            printf("(Network) io_uring created in SQPOLL Mode (Classic)\n");
        } else {
            // Standard
            memset(&params, 0, sizeof(params));
            params.flags = IORING_SETUP_SINGLE_ISSUER;
            
            ret = io_uring_queue_init_params(URING_ENTRIES, &g_ring, &params);
            if (ret == 0) {
                 printf("(Network) io_uring created in Single-Issuer Mode\n");
            } else {
                 // Basic
                 ret = io_uring_queue_init(URING_ENTRIES, &g_ring, 0);
                 if (ret == 0) printf("(Network) io_uring created in Standard Mode\n");
            }
        }
    }

    if (ret < 0) {
        errno = -ret;
        perror("io_uring_queue_init failed");
        return -1;
    }

    memset(g_fds, 0, sizeof(g_fds));

    /* Registers files to implement a fixed filet able rather than lookup in the process table */
    int* register_buf = malloc(MAX_FDS * sizeof(int));
    if (register_buf) {
        for (int i = 0; i < MAX_FDS; i++) register_buf[i] = -1;
        
        ret = io_uring_register_files(&g_ring, register_buf, MAX_FDS);
        free(register_buf);

        if (ret < 0) {
            fprintf(stderr, "(Network) Warning: Failed to register files (%d).\n", ret);
            g_files_registered = 0;
        } else {
            g_files_registered = 1;
        }
    }
    
    return 0;
}

static int backend_make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) return -1;
    return 0;
}

static int backend_socket_create_listener(int port) {
    int listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0) {
        perror("socket() failed");
        return -1;
    }

    int optval = 1;
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(listener_fd);
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(port);

    if (bind(listener_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        close(listener_fd);
        return -1;
    }

    if (listen(listener_fd, 128) < 0) {
        perror("listen() failed");
        close(listener_fd);
        return -1;
    }

    if (backend_make_nonblocking(listener_fd) < 0) {
        close(listener_fd);
        return -1;
    }

    if (listener_fd >= MAX_FDS) {
        fprintf(stderr, "listener_fd exceeds MAX_FDS\n");
        close(listener_fd);
        return -1;
    }

    FdState* st = &g_fds[listener_fd];
    memset(st, 0, sizeof(*st));
    st->type = FD_TYPE_LISTENER;

    if (backend_watch_add(listener_fd, IO_EVENT_READ, (void*)(intptr_t)listener_fd) < 0) {
        close(listener_fd);
        fdstate_reset(listener_fd);
        return -1;
    }

    if (submit_accept_request(listener_fd) < 0) {
        perror("submit_accept_request");
    }

    int sret = io_uring_submit(&g_ring);
    if (sret < 0) {
        errno = -sret;
        perror("io_uring_submit (listener init)");
        backend_watch_del(listener_fd);
        close(listener_fd);
        fdstate_reset(listener_fd);
        return -1;
    }

    printf("(Network) Server listening on port %d (fd: %d, async io_uring)\n", port, listener_fd);
    return listener_fd;
}

/* Done to retriev the IP Address, is blocking because it uses accept */
static int backend_socket_accept(int listener_fd, char* ip_buf, size_t ip_buf_len) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(listener_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        return -1;
    }

    if (ip_buf != NULL && ip_buf_len > 0) {
        const char* ip = inet_ntoa(client_addr.sin_addr);
        strncpy(ip_buf, ip, ip_buf_len);
        ip_buf[ip_buf_len - 1] = '\0';
    }

    return client_fd;
}

static void backend_socket_close(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return;
    backend_watch_del(fd);
    close(fd);
    fdstate_reset(fd);
}

/* Registers new FD in the fixed file table and queues polling */
static int backend_watch_add(int fd, int events, void* user_data) {
    if (fd < 0 || fd >= MAX_FDS) return -1;
    FdState* st = &g_fds[fd];

    st->active    = 1;
    st->interests = events;
    st->user_data = user_data;

    if (st->type == FD_TYPE_NONE) {
        st->type = FD_TYPE_CLIENT;
    }

    if (g_files_registered) {
        if (io_uring_register_files_update(&g_ring, fd, &fd, 1) < 0) {
             perror("io_uring_register_files_update (add)");
        }
    }

    submit_poll_request(fd);

    int ret = io_uring_submit(&g_ring);
    if (ret < 0) {
        errno = -ret;
        perror("io_uring_submit (watch_add)");
        st->active = 0;
        return -1;
    }

    printf("(Network) Added fd %d to io_uring\n", fd);
    return 0;
}

/* Modifies the event we are looking for */
static int backend_watch_mod(int fd, int events, void* user_data) {
    if (fd < 0 || fd >= MAX_FDS) return -1;
    FdState* st = &g_fds[fd];

    if (!st->active) {
        return backend_watch_add(fd, events, user_data);
    }

    st->interests = events;
    st->user_data = user_data;

    submit_poll_request(fd);

    int ret = io_uring_submit(&g_ring);
    if (ret < 0) {
        errno = -ret;
        perror("io_uring_submit (watch_mod)");
        return -1;
    }

    return 0;
}

/* Kills a client, kicks it off the ring and removes FD from the fixed table */
static int backend_watch_del(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return -1;
    FdState* st = &g_fds[fd];

    if (!st->active) return 0;

    st->active    = 0;
    st->interests = 0;
    st->user_data = NULL;

    struct io_uring_sqe* sqe = io_uring_get_sqe(&g_ring);
    if (sqe) {
        io_uring_prep_cancel(sqe, (void*)make_tag(fd, 0), IORING_ASYNC_CANCEL_ALL);
        io_uring_sqe_set_data(sqe, NULL);
        io_uring_submit(&g_ring);
    }

    if (g_files_registered) {
        int minus_one = -1;
        io_uring_register_files_update(&g_ring, fd, &minus_one, 1);
    }

    printf("(Network) Removed fd %d from io_uring\n", fd);
    return 0;
}

static int backend_poll(IOEvent* events, int max_events, int timeout_ms) {
    (void)timeout_ms;

    /* Processes request once a poll in a batch system, greatly improved throughput
     (90k -> 130k )*/
    int sret = io_uring_submit(&g_ring);
    if (sret < 0) {
        errno = -sret;
        perror("io_uring_submit (poll start)");
        return -1;
    }

    struct io_uring_cqe* cqe = NULL;
    int ret = io_uring_wait_cqe(&g_ring, &cqe);
    if (ret < 0) {
        if (ret == -EAGAIN) return 0;
        errno = -ret;
        perror("io_uring_wait_cqe");
        return -1;
    }

    unsigned head;
    int count = 0;

    /* Loops through completion queue , populates IOEvent array for server.c */
    io_uring_for_each_cqe(&g_ring, head, cqe) {
        if (count >= max_events) break;

        intptr_t tag = (intptr_t)io_uring_cqe_get_data(cqe);
        int fd, op;
        decode_tag(tag, &fd, &op);

        if (fd < 0 || fd >= MAX_FDS) {
            continue;
        }

        FdState* st = &g_fds[fd];

        if (!st->active) {
            continue;
        }

        IOEvent* ev = &events[count];
        ev->fd        = fd;
        ev->user_data = st->user_data;
        ev->events    = 0;
        ev->result    = cqe->res;

        if (op == 0) {
            /* POLL completion */
            short mask = (short)cqe->res;

            if (cqe->res < 0 || (mask & (POLLERR | POLLHUP | POLLNVAL))) {
                ev->events |= IO_EVENT_ERROR;
            }

            if (st->active) {
                submit_poll_request(fd);
            }

        } else if (op == 1) {
            /* ACCEPT completion */
            if (cqe->res < 0) {
                ev->events |= IO_EVENT_ERROR;
            } else {
                ev->events |= IO_EVENT_READ;
                ev->result  = cqe->res;
            }

            if (st->active) {
                submit_accept_request(fd);
            }

        } else if (op == 2) {
            /* READ completion */
            if (cqe->res <= 0) {
                st->read_len = 0;
                ev->events   |= IO_EVENT_ERROR;
            } else {
                st->read_len = (size_t)cqe->res;
                ev->events   |= IO_EVENT_READ;
            }

        } else if (op == 3) {
            /* WRITE completion */
            if (cqe->res < 0) {
                ev->events |= IO_EVENT_ERROR;
            } else {
                st->last_write_res = cqe->res;
                ev->events |= IO_EVENT_WRITE;
            }
        }

        count++;
    }

    io_uring_cq_advance(&g_ring, count);
    return count;
}

/* Synchronous-style read/write (not used in async mode) */

static ssize_t backend_read(int fd, void* buf, size_t count) {
    return read(fd, buf, count);
}

static ssize_t backend_write(int fd, const void* buf, size_t count) {
    return write(fd, buf, count);
}

/* Async helpers */

/* Populates the buf with the states read_buf */
static int backend_get_read_buffer(int fd, BackendBuffer* buf) {
    if (fd < 0 || fd >= MAX_FDS || !buf) return -1;
    FdState* st = &g_fds[fd];
    if (!st->active || st->type != FD_TYPE_CLIENT) {
        return -1;
    }

    buf->data     = st->read_buf;
    buf->capacity = st->read_cap;
    buf->len      = st->read_len;


    return 0;
}

/* rearms an FD for a new read */
static int backend_re_arm_read(int fd) {
    if (fd < 0 || fd >= MAX_FDS) return -1;
    FdState* st = &g_fds[fd];
    if (!st->active || st->type != FD_TYPE_CLIENT) {
        return -1;
    }

    st->read_len = 0;
    if (submit_read_request(fd) < 0) {
        return -1;
    }
    return 0;
}

static ssize_t backend_submit_write(int fd, const void* buf, size_t count) {
    if (fd < 0 || fd >= MAX_FDS) return -1;
    if (!buf || count == 0) return 0;

    if (submit_write_request(fd, buf, count) < 0) return -1;
    return (ssize_t)count;
}

IOBackend iouring_backend = {.name                   = "io_uring",.is_async               = 1,.init                   = backend_init,.socket_create_listener = backend_socket_create_listener,.socket_accept          = backend_socket_accept,.socket_close           = backend_socket_close,.socket_make_nonblocking= backend_make_nonblocking,.watch_add              = backend_watch_add,.watch_mod              = backend_watch_mod,.watch_del              = backend_watch_del,.poll                   = backend_poll,.read                   = backend_read,.write                  = backend_write,.get_read_buffer        = backend_get_read_buffer,.re_arm_read            = backend_re_arm_read,.submit_write           = backend_submit_write
};