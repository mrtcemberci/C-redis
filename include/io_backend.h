#ifndef IO_BACKEND_H
#define IO_BACKEND_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

extern bool g_is_async_mode;

/* ------------- Abstract Event Types ------------- */
#define IO_EVENT_READ  (1 << 0)
#define IO_EVENT_WRITE (1 << 1)
#define IO_EVENT_ERROR (1 << 2) 

/* ------------- Backend buffer for zero-copy ------------- */
/* In async/io_uring mode, this represents a kernel-managed buffer. */
typedef struct {
    char*  data;      // Pointer to buffer memory
    size_t capacity;  // Allocated size
    size_t len;       // Valid/used length (set on read completion)
} BackendBuffer;

/* ------------- Abstract Event Structure ------------- */
/*
 * For synchronous backends (epoll):
 *   - fd:      usual descriptor
 *   - events:  IO_EVENT_READ/WRITE/ERROR
 *   - user_data: your FD or client pointer as before
 *   - result:  optional; usually 0 or ignored
 *
 * For async backends (io_uring):
 *   - fd:      relevant fd for this completion (socket, listener, etc.)
 *   - events:  same flags
 *   - user_data: whatever backend associated with the CQE
 *   - result:  completion result (bytes read/written, new fd, or error code)
 */
typedef struct {
    int fd;
    uint32_t events;
    void* user_data;
    ssize_t result;
} IOEvent;

/* ------------- The V-Table Interface ------------- */
typedef struct {
    const char* name;

    /* Is this backend async (io_uring-style) or sync (epoll-style)? */
    int is_async;  // 0 = sync, 1 = async

    /* Initialization */
    int (*init)(void);

    /* Socket Lifecycle */
    int  (*socket_create_listener)(int port);
    int  (*socket_accept)(int listener_fd, char* ip_buf, size_t ip_buf_len);
    void (*socket_close)(int fd);
    int  (*socket_make_nonblocking)(int fd);

    /* Event Loop Management */
    int (*watch_add)(int fd, int events, void* user_data);
    int (*watch_mod)(int fd, int events, void* user_data);
    int (*watch_del)(int fd);

    /* The Main Wait Function */
    int (*poll)(IOEvent* events, int max_events, int timeout_ms);

    /* Synchronous-style data transfer (epoll) */
    ssize_t (*read)(int fd, void* buf, size_t count);
    ssize_t (*write)(int fd, const void* buf, size_t count);

    /**
     * get_read_buffer:
     *  Async helper: Get the buffer where the backend delivers data.
     */
    int (*get_read_buffer)(int fd, BackendBuffer* buf);

    /**
     * re_arm_read:
     *  Async helper: tell backend we are done parsing current buffer and
     *  want to schedule the next read.
     *  Returns 0 on success, -1 on error.
     */
    int (*re_arm_read)(int fd);

    /**
     * submit_write:
     *  Async helper: queue a write job.
     */
    ssize_t (*submit_write)(int fd, const void* buf, size_t count);

} IOBackend;

/* ------------- Active backend pointer ------------- */
extern IOBackend* g_backend;

/* ------------- Available backends ------------- */
extern IOBackend epoll_backend;
extern IOBackend iouring_backend;
extern IOBackend xdp_backend;

#endif