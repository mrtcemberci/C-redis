#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <errno.h>

#include "hashmap.h"
#include "parser.h"
#include "network.h"
#include "client.h"

#define SERVER_PORT 6379
#define MAX_EVENTS 64
#define RESPONSE_BUFFER_SIZE 1024 // For formatting GET responses

// The global database
HashMap* g_database = NULL;


void handle_new_connection(int listener_fd);
void handle_client_event(int client_fd);
void handle_client_disconnect(Client* client);
void process_commands_in_buffer(Client* client);
void execute_command(Client* client, Command* cmd, ParseResult parse_status);


int main(void) {

    // Create the database
    g_database = hashmap_create();
    if (g_database == NULL) {
        perror("Failed to create hashmap");
        return 1;
    }
    
    // Create the epoll instance
    if (network_init() < 0) {
        fprintf(stderr, "Failed to init network\n");
        return 1;
    }
    
    // Create the listening socket
    int listener_fd = network_listen(SERVER_PORT);
    if (listener_fd < 0) {
        fprintf(stderr, "Failed to start listener\n");
        return 1;
    }

    struct epoll_event events[MAX_EVENTS];

    // Main event loop
    printf("--- Server is running ---\n");
    while (1) {
        // Epoll wait on the epoll_fd for MAX_EVENTS to be stored in the events array
        int n_ready = epoll_wait(g_epoll_fd, events, MAX_EVENTS, -1);
        if (n_ready < 0) {
            // A signal (like Ctrl+C) can interrupt epoll_wait
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait failed");
            continue;
        }

        for (int i = 0; i < n_ready; i++) {
            int fd = events[i].data.fd;

            if (fd == listener_fd) {
                // The listener socket is awake, could be a new connection
                handle_new_connection(listener_fd);
            } else {
                // Existing client message
                
                // TODO: Check for EPOLLOUT for writing
                
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    // Error on the socket
                    printf("(Server) Error on socket fd %d\n", fd);
                    handle_client_disconnect(client_get(fd));
                }
                else if (events[i].events & EPOLLIN) {
                    // Data to read
                    handle_client_event(fd);
                }
            }
        }
    }

    // Cleanup, but is kind of unreachable
    hashmap_free(g_database);
    close(listener_fd);
    return 0;
}


/**
 *  Called when a new client connects to the listener_fd
 */
void handle_new_connection(int listener_fd) {
    // We must accept() in a loop because we use Edge-Triggered (EPOLLET)
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Accept new file descriptor for the client
        int client_fd = accept(listener_fd, (struct sockaddr*)&client_addr, &client_len);

        if (client_fd < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                break; // No more clients to accept
            }
            perror("accept");
            break; // A real error occurred
        }

        // Get the client's IP as a string
        char* client_ip = inet_ntoa(client_addr.sin_addr);
        printf("(Server) Accepted connection from %s on fd %d\n", client_ip, client_fd);

        // (IP Whitelisting check would go here)

        // Make it non blocking
        if (make_socket_non_blocking(client_fd) < 0) {
            close(client_fd);
            continue; // Go to next client
        }
        
        // Create a client and add it to the our client array in client.c
        if (client_create(client_fd) == NULL) {
            fprintf(stderr, "Failed to create client for fd %d\n", client_fd);
            close(client_fd);
            continue;
        }

        // Add it to our epoll instance
        if (network_add_fd_to_epoll(client_fd) < 0) {
            // client_free will close the fd
            client_free(client_get(client_fd));
        }
    }
}

/**
 *  Called when epoll says a client has data to read (EPOLLIN)
 */
void handle_client_event(int client_fd) {
    Client* client = client_get(client_fd);
    if (client == NULL) {
        fprintf(stderr, "Got event from unknown fd %d\n", client_fd);
        network_remove_fd_from_epoll(client_fd);
        close(client_fd);
        return;
    }
    
    // Read the data the client wants to tell us
    ClientReadResult read_status = client_read_data(client);
    
    // Check the result of the read
    if (read_status == READ_DISCONNECTED || read_status == READ_ERROR) {
        handle_client_disconnect(client);
        return;
    }
    
    // (read_status == READ_OK)
    // The buffer has new data, try to process it
    process_commands_in_buffer(client);
}

/**
 *   Scans the client's buffer for full commands
 * and processes them, may not succeeded if buffer is fully arrived yet.
 */
void process_commands_in_buffer(Client* client) {
    // Loop as long as we can find a newline (command) in the buffer
    while (1) {
        // Scan for a '\n'
        char* newline = memchr(client->read_buffer, '\n', client->read_buffer_len);

        if (newline == NULL) {
            // If no '\n' found, we're done. Wait for more data.
            break;
        }

        //  We found a full command.
        size_t line_len = (newline - client->read_buffer);
        
        // Temporarily set the newline to '\0' to treat it as a C-string
        *newline = '\0';

        // Parse and execute
        Command cmd;
        ParseResult parse_status = parse_line(client->read_buffer, &cmd);
        execute_command(client, &cmd, parse_status);

        //   Remove the processed command from the buffer.
        //   Calculate how much data is *left* in the buffer.
        size_t remaining_len = client->read_buffer_len - (line_len + 1);

        // Shift the remaining data to the front
        memmove(client->read_buffer, newline + 1, remaining_len);
        client->read_buffer_len = remaining_len;
        
        // Loop again to see if there's another full command
    }
}

/**
 *  Executes a single parsed command against the database
 */
void execute_command(Client* client, Command* cmd, ParseResult parse_status) {
    char response_buffer[RESPONSE_BUFFER_SIZE];

    if (parse_status != PARSE_SUCCESS) {
        const char* error_msg;
        if (parse_status == PARSE_ERROR_UNCLOSED_QUOTE) {
            error_msg = "(error) Protocol error: unclosed quote\n";
        } else if (parse_status == PARSE_ERROR_TOO_MANY_ARGS) {
            error_msg = "(error) Protocol error: too many arguments\n";
        } else {
            error_msg = "(error) Protocol error: invalid syntax\n";
        }
        // Write back the clients socket the error 
        write(client->fd, error_msg, strlen(error_msg));
        return;
    }

    // Check for an empty line
    if (cmd->argc == 0) {
        // Client just hit enter, do nothing.
        return;
    }
    
    // Process "SET" command
    if (strcasecmp(cmd->argv[0], "SET") == 0) {
        if (cmd->argc != 3) {
            const char* error_msg = "(error) ERR wrong number of arguments for 'set' command\n";
            write(client->fd, error_msg, strlen(error_msg));
            return;
        }

        printf("(Client %d) EXEC: SET %s = %s\n", client->fd, cmd->argv[1], cmd->argv[2]);
        
        if (hashmap_set(g_database, cmd->argv[1], cmd->argv[2]) == 0) {
            const char* ok_msg = "OK\n";
            write(client->fd, ok_msg, strlen(ok_msg));
        } else {
            const char* error_msg = "(error) ERR failed to set key\n";
            write(client->fd, error_msg, strlen(error_msg));
        }
        return;
    }

    //  Process "GET" command
    if (strcasecmp(cmd->argv[0], "GET") == 0) {
        if (cmd->argc != 2) {
            const char* error_msg = "(error) ERR wrong number of arguments for 'get' command\n";
            write(client->fd, error_msg, strlen(error_msg));
            return;
        }

        printf("(Client %d) EXEC: GET %s\n", client->fd, cmd->argv[1]);
        
        const char* val = hashmap_get(g_database, cmd->argv[1]);
        
        if (val == NULL) {
            const char* nil_msg = "(nil)\n";
            write(client->fd, nil_msg, strlen(nil_msg));
        } else {
            // Format the string response: "$<len>\r\n<value>\r\n"
            // For our simple protocol, we'll just send: "\"<value>\"\n"
            int len = snprintf(response_buffer, RESPONSE_BUFFER_SIZE, "\"%s\"\n", val);
            if (len >= RESPONSE_BUFFER_SIZE) {
                // Value was too large for our response buffer
                const char* error_msg = "(error) ERR value too large to send\n";
                write(client->fd, error_msg, strlen(error_msg));
            } else {
                write(client->fd, response_buffer, len);
            }
        }
        return;
    }
    
    // Process "DEL" command
    if (strcasecmp(cmd->argv[0], "DEL") == 0) {
        if (cmd->argc != 2) {
            const char* error_msg = "(error) ERR wrong number of arguments for 'del' command\n";
            write(client->fd, error_msg, strlen(error_msg));
            return;
        }

        printf("(Client %d) EXEC: DEL %s\n", client->fd, cmd->argv[1]);
        
        hashmap_delete(g_database, cmd->argv[1]);
        
        // Return the number of keys deleted
        const char* ok_msg = "(integer) 1\n";
        write(client->fd, ok_msg, strlen(ok_msg));
        return;
    }

    printf("(Client %d) Unknown command: %s\n", client->fd, cmd->argv[0]);

    // Unknown command
    int len = snprintf(response_buffer, RESPONSE_BUFFER_SIZE, 
                       "(error) ERR unknown command '%s'\n", cmd->argv[0]);
    write(client->fd, response_buffer, len);
}

/**
 *  Called when a client disconnects (read returns 0 or error)
 */
void handle_client_disconnect(Client* client) {
    if (client == NULL) {
        return; // Already freed
    }
    
    printf("(Server) Client %d disconnected.\n", client->fd);
    
    network_remove_fd_from_epoll(client->fd);
    client_free(client); // This also closes the fd
}