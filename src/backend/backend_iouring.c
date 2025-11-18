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
#include <sys/epoll.h> 

#include "io_backend.h"

#define URING_ENTRIES 256
#define MAX_FDS 4096 

static struct io_uring g_ring;

struct WatchState {
    int active;
    uint32_t events;
    void* user_data;
};

static struct WatchState g_watches[MAX_FDS];

static int backend_init(void);
static int backend_make_nonblocking(int fd);
static int backend_socket_create_listener(int port);
static int backend_socket_accept(int listener_fd, char* ip_buf, size_t ip_buf_len);
static void backend_socket_close(int fd);
static int backend_watch_add(int fd, int events, void* user_data);
static int backend_watch_mod(int fd, int events, void* user_data);
static int backend_watch_del(int fd);
static int backend_poll(IOEvent* events, int max_events, int timeout_ms);
static ssize_t backend_read(int fd, void* buf, size_t count);
static ssize_t backend_write(int fd, const void* buf, size_t count);



static void submit_poll_request(int fd) {
    if (fd < 0 || fd >= MAX_FDS || !g_watches[fd].active) return;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&g_ring);
    if (!sqe) return; // SQ Full, event dropped (robustness improvement needed for prod)

    short poll_mask = 0;
    if (g_watches[fd].events & IO_EVENT_READ) poll_mask |= POLLIN;
    if (g_watches[fd].events & IO_EVENT_WRITE) poll_mask |= POLLOUT;
    
    poll_mask |= EPOLLET; 

    io_uring_prep_poll_add(sqe, fd, poll_mask);
    io_uring_sqe_set_data(sqe, (void*)(intptr_t)fd);
}

static void cancel_poll_request(int fd) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&g_ring);
    if (!sqe) return;

    io_uring_prep_cancel(sqe, (void*)(intptr_t)fd, 0);
    io_uring_sqe_set_data(sqe, NULL); 
    io_uring_submit(&g_ring);
}



static int backend_init(void) {
    if (io_uring_queue_init(URING_ENTRIES, &g_ring, 0) < 0) {
        perror("io_uring_queue_init failed");
        return -1;
    }
    memset(g_watches, 0, sizeof(g_watches));
    printf("(Network) io_uring instance created\n");
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
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

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
    
    if (backend_watch_add(listener_fd, IO_EVENT_READ, (void*)(intptr_t)listener_fd) < 0) {
        close(listener_fd);
        return -1;
    }

    printf("(Network) Server listening on port %d (fd: %d)\n", port, listener_fd);
    return listener_fd;
}

static int backend_socket_accept(int listener_fd, char* ip_buf, size_t ip_buf_len) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_fd = accept(listener_fd, (struct sockaddr*)&client_addr, &client_len);
    
    if (client_fd >= 0 && ip_buf != NULL) {
        char* ip = inet_ntoa(client_addr.sin_addr);
        strncpy(ip_buf, ip, ip_buf_len);
        ip_buf[ip_buf_len - 1] = '\0';
    }
    
    return client_fd;
}

static void backend_socket_close(int fd) {
    close(fd);
}

static int backend_watch_add(int fd, int events, void* user_data) {
    if (fd >= MAX_FDS) return -1;

    g_watches[fd].active = 1;
    g_watches[fd].events = events;
    g_watches[fd].user_data = user_data;

    submit_poll_request(fd);
    io_uring_submit(&g_ring);

    printf("(Network) Added fd %d to io_uring\n", fd);
    return 0;
}

static int backend_watch_mod(int fd, int events, void* user_data) {
    if (fd >= MAX_FDS) return -1;

    cancel_poll_request(fd);

    g_watches[fd].active = 1;
    g_watches[fd].events = events;
    g_watches[fd].user_data = user_data;

    submit_poll_request(fd);
    io_uring_submit(&g_ring);
    
    return 0;
}

static int backend_watch_del(int fd) {
    if (fd >= MAX_FDS) return -1;

    if (g_watches[fd].active) {
        cancel_poll_request(fd);
        g_watches[fd].active = 0;
        printf("(Network) Removed fd %d from io_uring\n", fd);
    }
    return 0;
}

static int backend_poll(IOEvent* events, int max_events, int timeout_ms) {
    struct io_uring_cqe *cqe;
    
    int ret;
    if (timeout_ms == 0) {
         ret = io_uring_peek_cqe(&g_ring, &cqe);
    } else {
         ret = io_uring_wait_cqe(&g_ring, &cqe);
    }

    if (ret < 0) {
        if (ret == -EAGAIN) return 0; 
        return -1;
    }

    unsigned head;
    int count = 0;

    io_uring_for_each_cqe(&g_ring, head, cqe) {
        if (count >= max_events) break;

        int fd = (int)(intptr_t)cqe->user_data;

        if (cqe->res >= 0) {
            events[count].fd = fd;
            events[count].events = 0;
            
            if (fd < MAX_FDS) {
                events[count].user_data = g_watches[fd].user_data;
            }

            if (cqe->res & POLLIN)  events[count].events |= IO_EVENT_READ;
            if (cqe->res & POLLOUT) events[count].events |= IO_EVENT_WRITE;
            if (cqe->res & (POLLERR|POLLHUP)) events[count].events |= IO_EVENT_ERROR;

            if (fd < MAX_FDS && g_watches[fd].active) {
                submit_poll_request(fd);
            }
            
            count++;
        } 
    }

    io_uring_cq_advance(&g_ring, count);
    
    if (count > 0) {
        io_uring_submit(&g_ring);
    }

    return count;
}

static ssize_t backend_read(int fd, void* buf, size_t count) {
    return read(fd, buf, count);
}

static ssize_t backend_write(int fd, const void* buf, size_t count) {
    return write(fd, buf, count);
}

IOBackend iouring_backend = {
    .name = "io_uring",
    .init = backend_init,
    .socket_create_listener = backend_socket_create_listener,
    .socket_accept = backend_socket_accept,
    .socket_close = backend_socket_close,
    .socket_make_nonblocking = backend_make_nonblocking,
    .watch_add = backend_watch_add,
    .watch_mod = backend_watch_mod,
    .watch_del = backend_watch_del,
    .poll = backend_poll,
    .read = backend_read,
    .write = backend_write
};