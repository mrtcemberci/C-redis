#ifndef IO_BACKEND_H
#define IO_BACKEND_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// Abstract Event Types
// We map these to the backend specific flags (e.g. EPOLLIN/EPOLLOUT)
#define IO_EVENT_READ  (1 << 0)
#define IO_EVENT_WRITE (1 << 1)
#define IO_EVENT_ERROR (1 << 2) // For EPOLLERR/EPOLLHUP

// Abstract Event Structure
typedef struct {
    int fd;            // The file descriptor (optional, backend specific)
    uint32_t events;   // Mask of IO_EVENT_*
    void* user_data;   // Context pointer (We will store the FD here as intptr_t to match original logic)
} IOEvent;

// The V-Table Interface
typedef struct {
    const char* name;

    // Initialization
    int (*init)(void);
    
    // Socket Lifecycle
    int (*socket_create_listener)(int port);
    int (*socket_accept)(int listener_fd, char* ip_buf, size_t ip_buf_len);
    void (*socket_close)(int fd);
    int (*socket_make_nonblocking)(int fd);

    // Event Loop Management
    int (*watch_add)(int fd, int events, void* user_data);
    int (*watch_mod)(int fd, int events, void* user_data);
    int (*watch_del)(int fd);
    
    // The Main Wait Function
    int (*poll)(IOEvent* events, int max_events, int timeout_ms);

    // Data Transfer
    ssize_t (*read)(int fd, void* buf, size_t count);
    ssize_t (*write)(int fd, const void* buf, size_t count);

} IOBackend;

// The active backend pointer
extern IOBackend* g_backend;

// Available backends
extern IOBackend epoll_backend;

#endif