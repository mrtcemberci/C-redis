#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "io_backend.h"

static int g_epoll_fd = -1;


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



static int backend_init(void) {
    g_epoll_fd = epoll_create1(0);
    if (g_epoll_fd < 0) {
        perror("epoll_create1 failed");
        return -1;
    }
    printf("(Network) Epoll instance created (fd: %d)\n", g_epoll_fd);
    return 0;
}

static int backend_make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL)");
        return -1;
    }
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

    if (client_fd >= 0 && ip_buf != NULL && ip_buf_len > 0) {
        const char* ip = inet_ntoa(client_addr.sin_addr);
        strncpy(ip_buf, ip, ip_buf_len);
        ip_buf[ip_buf_len - 1] = '\0';
    }

    return client_fd;
}

static void backend_socket_close(int fd) {
    close(fd);
}

static int backend_watch_add(int fd, int events, void* user_data) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    ev.events = EPOLLET;
    if (events & IO_EVENT_READ)  ev.events |= EPOLLIN;
    if (events & IO_EVENT_WRITE) ev.events |= EPOLLOUT;
    ev.data.ptr = user_data;

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        perror("epoll_ctl ADD failed");
        return -1;
    }

    printf("(Network) Added fd %d to epoll\n", fd);
    return 0;
}

static int backend_watch_mod(int fd, int events, void* user_data) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    ev.events = EPOLLET;
    if (events & IO_EVENT_READ)  ev.events |= EPOLLIN;
    if (events & IO_EVENT_WRITE) ev.events |= EPOLLOUT;
    ev.data.ptr = user_data;

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        perror("epoll_ctl MOD failed");
        return -1;
    }
    return 0;
}

static int backend_watch_del(int fd) {
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        perror("epoll_ctl DEL failed");
    } else {
        printf("(Network) Removed fd %d from epoll\n", fd);
    }
    return 0;
}

static int backend_poll(IOEvent* events, int max_events, int timeout_ms) {
    struct epoll_event ep_events[max_events];

    int n = epoll_wait(g_epoll_fd, ep_events, max_events, timeout_ms);
    if (n < 0) {
        return n; // errno is set by epoll_wait
    }

    for (int i = 0; i < n; i++) {
        events[i].fd        = (int)(intptr_t)ep_events[i].data.ptr;
        events[i].user_data = ep_events[i].data.ptr;
        events[i].events    = 0;
        events[i].result    = 0; // not used in sync mode

        if (ep_events[i].events & (EPOLLERR | EPOLLHUP)) {
            events[i].events |= IO_EVENT_ERROR;
        }
        if (ep_events[i].events & EPOLLIN) {
            events[i].events |= IO_EVENT_READ;
        }
        if (ep_events[i].events & EPOLLOUT) {
            events[i].events |= IO_EVENT_WRITE;
        }
    }
    return n;
}

static ssize_t backend_read(int fd, void* buf, size_t count) {
    return read(fd, buf, count);
}

static ssize_t backend_write(int fd, const void* buf, size_t count) {
    return write(fd, buf, count);
}

static int backend_get_read_buffer(int fd, BackendBuffer* buf) {
    (void)fd;
    if (!buf) return -1;

    buf->data     = NULL;
    buf->capacity = 0;
    buf->len      = 0;
    errno = EAGAIN;
    return -1;
}

static int backend_re_arm_read(int fd) {
    (void)fd;
    return 0;
}

static ssize_t backend_submit_write(int fd, const void* buf, size_t count) {
    return backend_write(fd, buf, count);
}

/* All the async only functions are not used in epoll/sync mode */

IOBackend epoll_backend = {.name                   = "epoll",.is_async               = 0,  /* sync mode */.init                   = backend_init,.socket_create_listener = backend_socket_create_listener,.socket_accept          = backend_socket_accept,.socket_close           = backend_socket_close,.socket_make_nonblocking= backend_make_nonblocking,.watch_add              = backend_watch_add,.watch_mod              = backend_watch_mod,.watch_del              = backend_watch_del,.poll                   = backend_poll,.read                   = backend_read,.write                  = backend_write,.get_read_buffer        = backend_get_read_buffer,.re_arm_read            = backend_re_arm_read,.submit_write           = backend_submit_write
};