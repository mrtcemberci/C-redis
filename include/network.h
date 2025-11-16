#ifndef NETWORK_H
#define NETWORK_H

extern int g_epoll_fd;

/**
 *  Initializes the epoll instance.
 *  0 on success, -1 on failure.
 */
int network_init(void);

/**
 *  Creates the listener socket, binds to the port,
 * and adds it to the epoll instance.
 *
 *  The port number to listen on (e.g., 6379)
 *  The listener_fd on success, or -1 on failure.
 */
int network_listen(int port);

/**
 *  Adds a file descriptor to the epoll watch list.
 *
 *  fd The fd to add.
 *  0 on success, -1 on failure.
 */
int network_add_fd_to_epoll(int fd);

/**
 *  Removes a file descriptor from the epoll watch list.
 *
 *  fd The fd to remove.
 */
void network_remove_fd_from_epoll(int fd);

/**
 *  Makes a file descriptor non-blocking.
 * This is CRITICAL for epoll.
 *
 *  fd The fd to make non-blocking.
 *  0 on success, -1 on failure.
 */
int make_socket_non_blocking(int fd);


#endif // NETWORK_H