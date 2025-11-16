#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <fcntl.h> 
#include <errno.h>
#include <string.h>

#include "network.h"

// Define the global epoll fd
int g_epoll_fd = -1;


/**
 * Creates the master epoll file descriptor.
 */
int network_init(void) {
    g_epoll_fd = epoll_create1(0);
    if (g_epoll_fd < 0) {
        perror("epoll_create1 failed");
        return -1;
    }
    printf("(Network) Epoll instance created (fd: %d)\n", g_epoll_fd);
    return 0;
}

/**
 * Makes a file descriptor non-blocking.
 */
int make_socket_non_blocking(int fd) {
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

/**
 *  Adds a file descriptor to the epoll watch list.
 */
int network_add_fd_to_epoll(int fd) {
    struct epoll_event event;
    event.data.fd = fd;
    // EPOLLIN = "Ready to Read"
    // EPOLLET = "Edge-Triggered" (The doorbell)
    event.events = EPOLLIN | EPOLLET; 
    
    /* Pass EPOLL_CTL_ADD to add to the epoll */
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        perror("epoll_ctl ADD failed");
        return -1;
    }
    printf("(Network) Added fd %d to epoll\n", fd);
    return 0;
}

/**
 *  Removes a file descriptor from the epoll watch list.
 */
void network_remove_fd_from_epoll(int fd) {
    /* PASs EPOLL_CTL_DEL to delete from EPOLL watch list */
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        perror("epoll_ctl DEL failed");
    } else {
        printf("(Network) Removed fd %d from epoll\n", fd);
    }
}

/**
 * Start listening on given port 
 */
int network_listen(int port) {

    /* AF_INET = ADDRESS FAMILY-INTERNET (IPV4)*/
    /* SOCK_STREAM = starts a socket that is continuous streaming */
    /* 0 means use the default protocol for this family (IPV4)*/
    int listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0) {
        perror("socket() failed");
        return -1;
    }

    /* Allows the socket to be used immediately, even if it is busy */
    /* listener_fd = the socket fd 
       SOL_SOCKET = general socket option 
       SO_REUSEADDR = turn on reuse address feature 
       optval = turns on reuse address
    */
    int optval = 1;
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(listener_fd);
        return -1;
    }

    // Bind the socket to our IP and port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on 0.0.0.0
    server_addr.sin_port = htons(port);       // Convert port to network byte order

    /* Binds the file descriptor of the socket to the server address struct */
    if (bind(listener_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        close(listener_fd);
        return -1;
    }

    /* Listen for connections */
    if (listen(listener_fd, 128) < 0) { // 128 = backlog size
        perror("listen() failed");
        close(listener_fd);
        return -1;
    }

    //  Make the listener non-blocking (so accept() doesn't block)
    if (make_socket_non_blocking(listener_fd) < 0) {
        close(listener_fd);
        return -1;
    }

    //  Add the listener to our epoll list
    if (network_add_fd_to_epoll(listener_fd) < 0) {
        close(listener_fd);
        return -1;
    }

    printf("(Network) Server listening on port %d (fd: %d)\n", port, listener_fd);
    return listener_fd;
}