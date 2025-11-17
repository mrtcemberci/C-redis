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

// Security rules
#define IDLE_TIMEOUT_SECONDS 60
#define TIMER_WHEEL_SLOTS (IDLE_TIMEOUT_SECONDS + 1) // 61 slots (0-60)
#define RATE_LIMIT_WINDOW_SECONDS 60
#define RATE_LIMIT_CONNECTIONS 100
#define BAN_DURATION_SECONDS 600

// The global database
HashMap* g_database = NULL;
HashMap* g_ip_counts = NULL;   // Tracks connection counts in the current window
HashMap* g_ip_bans = NULL; // Tracks banned ips
time_t g_current_server_time = 0;
time_t g_last_ip_reap_time = 0; // For our tumbling window, resets every RATE_lIMIT_WINDOW_SECONDS Seconds
Client* g_timer_wheel[TIMER_WHEEL_SLOTS] = {0}; // O(1) idle client reaper


void handle_new_connection(int listener_fd);
void handle_client_event(int client_fd);
void handle_client_disconnect(Client* client);
void handle_client_write(int client_fd);
void process_commands_in_buffer(Client* client);
void execute_command(Client* client, Command* cmd, ParseResult parse_status);

void timer_wheel_add(Client* client);
void timer_wheel_remove(Client* client);
void reap_idle_clients(void);

void reap_ban_list(void);


int main(void) {
    
    g_database = hashmap_create();
    g_ip_counts = hashmap_create();
    g_ip_bans = hashmap_create();
    
    if (g_database == NULL || g_ip_counts == NULL || g_ip_bans == NULL) {
        perror("Failed to create hashmaps");
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
    g_current_server_time = time(NULL);
    g_last_ip_reap_time = g_current_server_time;

    // Main event loop
    printf("--- Server is running ---\n");
    while (1) {
        g_current_server_time = time(NULL); // Get the time

        // Epoll wait on the epoll_fd for MAX_EVENTS to be stored in the events array
        /* 1000 ms is 1 second, force wakeup each second to do the reap check */
        int n_ready = epoll_wait(g_epoll_fd, events, MAX_EVENTS, 1000);
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
            uint32_t e = events[i].events; 

            if (fd == listener_fd) {
                handle_new_connection(listener_fd);
            } else {
                // Check for errors first
                if (e & (EPOLLERR | EPOLLHUP)) {
                    printf("(Server) Error on socket fd %d\n", fd);
                    handle_client_disconnect(client_get(fd));
                    continue; // Skip other checks
                }
                
                if (e & EPOLLOUT) {
                    // Data to write
                    handle_client_write(fd);
                }

                if (e & EPOLLIN) {
                    // Data to read
                    handle_client_event(fd);
                }
            }
        }

        /* O(1) reap of idle clients using the time wheel */
        reap_idle_clients();

        /* O(n) but happens not often, Reap the IP trackers (reset)*/
        if (g_current_server_time - g_last_ip_reap_time >= RATE_LIMIT_WINDOW_SECONDS) {
            printf("(Server) Tumbling rate-limit window. Resetting all IP counts.\n");
            hashmap_free(g_ip_counts);
            g_ip_counts = hashmap_create();
            g_last_ip_reap_time = g_current_server_time;
            reap_ban_list(); 
        }
    }

    // Cleanup, but is kind of unreachable
    hashmap_free(g_database);
    hashmap_free(g_ip_counts);
    hashmap_free(g_ip_bans);
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

        if (client_fd >= MAX_CLIENTS) {
            fprintf(stderr, "Too many clients! Denying fd %d\n", client_fd);
            close(client_fd);
            continue;
        }

        // Get the client's IP as a string
        char* client_ip = inet_ntoa(client_addr.sin_addr);

        const char* ban_expiry_str = hashmap_get(g_ip_bans, client_ip);
        if (ban_expiry_str != NULL) {
            time_t ban_expires = atol(ban_expiry_str);
            if (g_current_server_time < ban_expires) {
                // They are still banned.
                printf("(Server) Denied banned IP: %s\n", client_ip);
                close(client_fd);
                continue; // Get next client
            } else {
                // Ban expired. Remove them.
                printf("(Server) Ban expired for %s\n", client_ip);
                hashmap_delete(g_ip_bans, client_ip);
            }
        }

        int count = 0;
        const char* count_str = hashmap_get(g_ip_counts, client_ip);
        if (count_str != NULL) {
            count = atoi(count_str);
        }
        count++;

        if (count > RATE_LIMIT_CONNECTIONS) {
            // BAN THEM!
            printf("(Server) Banning IP for rate-limiting: %s\n", client_ip);
            
            // Set ban for 10 minutes from now
            time_t ban_expires = g_current_server_time + BAN_DURATION_SECONDS;
            char ban_expiry_str_buf[32];
            snprintf(ban_expiry_str_buf, 32, "%ld", ban_expires);
            
            hashmap_set(g_ip_bans, client_ip, ban_expiry_str_buf);
            
            // Delete them from the count map
            hashmap_delete(g_ip_counts, client_ip);
            
            close(client_fd);
            continue;
        }

        char new_count_str[32];
        snprintf(new_count_str, 32, "%d", count);
        hashmap_set(g_ip_counts, client_ip, new_count_str);

        printf("(Server) Accepted connection from %s on fd %d\n", client_ip, client_fd);

        // Make it non blocking
        if (make_socket_non_blocking(client_fd) < 0) {
            close(client_fd);
            continue; // Go to next client
        }
        
        // Create a client and add it to the our client array in client.c
        Client* new_client = client_create(client_fd);
        if (new_client == NULL) {
            fprintf(stderr, "Failed to create client for fd %d\n", client_fd);
            close(client_fd);
            continue;
        }

        // Add it to our epoll instance
        if (network_add_fd_to_epoll(client_fd) < 0) {
            // client_free will close the fd
            client_free(client_get(client_fd));
        }

        timer_wheel_add(new_client);
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
    const char* response_msg = NULL; // The final message to send

    //  Check if the parser failed
    if (parse_status != PARSE_SUCCESS) {
        if (parse_status == PARSE_ERROR_UNCLOSED_QUOTE) {
            response_msg = "(error) Protocol error: unclosed quote\n";
        } else if (parse_status == PARSE_ERROR_TOO_MANY_ARGS) {
            response_msg = "(error) Protocol error: too many arguments\n";
        } else {
            response_msg = "(error) Protocol error: invalid syntax\n";
        }
        printf("(Client %d) Parse Error: %s", client->fd, response_msg);
        goto queue_response; // Send the error
    }

    //  Check for an empty line
    if (cmd->argc == 0) {
        timer_wheel_remove(client); // Valid activity
        timer_wheel_add(client);
        return; // No response needed
    }
    
    //  Process "SET" command
    if (strcasecmp(cmd->argv[0], "SET") == 0) {
        if (cmd->argc != 3) {
            response_msg = "(error) ERR wrong number of arguments for 'set' command\n";
            goto queue_response;
        }
        
        if (hashmap_set(g_database, cmd->argv[1], cmd->argv[2]) == 0) {
            printf("(Client %d) EXEC: SET %s = ...\n", client->fd, cmd->argv[1]);
            response_msg = "OK\n";
        } else {
            response_msg = "(error) ERR failed to set key (OOM)\n";
        }
        goto reset_timer_and_queue;
    }

    //  Process "GET" command
    if (strcasecmp(cmd->argv[0], "GET") == 0) {
        if (cmd->argc != 2) {
            response_msg = "(error) ERR wrong number of arguments for 'get' command\n";
            goto queue_response;
        }
        
        printf("(Client %d) EXEC: GET %s\n", client->fd, cmd->argv[1]);
        const char* val = hashmap_get(g_database, cmd->argv[1]);
        
        if (val == NULL) {
            response_msg = "(nil)\n";
        } else {
            // Format the string response
            int len = snprintf(response_buffer, RESPONSE_BUFFER_SIZE, "\"%s\"\n", val);
            if (len < 0 || (size_t)len >= RESPONSE_BUFFER_SIZE) {
                response_msg = "(error) ERR value too large to send\n";
            } else {
                // It fit, so we use the stack buffer
                response_msg = response_buffer;
            }
        }
        goto reset_timer_and_queue;
    }
    
    // Process "DEL" command
    if (strcasecmp(cmd->argv[0], "DEL") == 0) {
        if (cmd->argc != 2) {
            response_msg = "(error) ERR wrong number of arguments for 'del' command\n";
            goto queue_response;
        }
        
        printf("(Client %d) EXEC: DEL %s\n", client->fd, cmd->argv[1]);
        hashmap_delete(g_database, cmd->argv[1]);
        response_msg = "(integer) 1\n";
        goto reset_timer_and_queue;
    }

    //  Unknown command
    printf("(Client %d) Unknown command: %s\n", client->fd, cmd->argv[0]);
    int len = snprintf(response_buffer, RESPONSE_BUFFER_SIZE, 
                       "(error) ERR unknown command '%s'\n", cmd->argv[0]);
    if (len > 0 && (size_t)len < RESPONSE_BUFFER_SIZE) {
        response_msg = response_buffer;
    } else {
        response_msg = "(error) ERR unknown command\n";
    }
    // Do not reset timer for unknown commands
    goto queue_response;


reset_timer_and_queue:
    timer_wheel_remove(client);
    timer_wheel_add(client);

queue_response:
    if (response_msg != NULL) {
        if (queue_client_response(client, response_msg) == -1) {
            // OOM trying to queue response. Disconnect them.
            printf("(Server) Client %d: OOM on write queue. Disconnecting.\n", client->fd);
            handle_client_disconnect(client);
            return;
        }
    }
    
    struct epoll_event event;
    event.data.fd = client->fd;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, client->fd, &event) < 0) {
        perror("epoll_ctl MOD (add EPOLLOUT) failed");
        handle_client_disconnect(client);
    }
}


/*
    Called when epoll says a client socket is ready to be WRITTEN TO
*/
void handle_client_write(int client_fd) {
    Client* client = client_get(client_fd);
    if (client == NULL) return;

    size_t bytes_to_send = client->write_buffer_len - client->write_buffer_sent;
    if (bytes_to_send == 0) {
        // WE have no more bytes to send, tell epoll to F OFF!
        goto stop_writing; 
    }

    // where to start sending
    char* data_start = client->write_buffer + client->write_buffer_sent;

    ssize_t bytes_written = write(client_fd, data_start, bytes_to_send);

    if (bytes_written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Kernel buffer is full, write later
            return; 
        }
        // A real error occurred
        perror("write() failed");
        handle_client_disconnect(client);
        return;
    }

    // Update how much we've sent
    client->write_buffer_sent += bytes_written;

    // Check if we're done
    if (client->write_buffer_sent == client->write_buffer_len) {
        // We have sent everything, GOODBYE BUFFER
        client->write_buffer_len = 0;
        client->write_buffer_sent = 0;

stop_writing: ;
        struct epoll_event event;
        event.data.fd = client_fd;
        event.events = EPOLLIN | EPOLLET; // Go back to READ-ONLY
        
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, client_fd, &event) < 0) {
            perror("epoll_ctl MOD (remove EPOLLOUT) failed");
            handle_client_disconnect(client);
        }
    }
}

/**
 *  Called when a client disconnects (read returns 0 or error)
 */
void handle_client_disconnect(Client* client) {
    if (client == NULL) {
        return; // Already freed
    }
    
    printf("(Server) Client %d disconnected.\n", client->fd);
    timer_wheel_remove(client);

    network_remove_fd_from_epoll(client->fd);
    client_free(client); // This also closes the fd
}

void timer_wheel_add(Client* client) {
    if (client == NULL) return;
    
    client->last_active_time = g_current_server_time;
    
    // Calculate which slot this client belongs in
    int slot = (client->last_active_time + IDLE_TIMEOUT_SECONDS) % TIMER_WHEEL_SLOTS;
    
    // Add to the front of that slot's linked list
    client->next = g_timer_wheel[slot];
    client->prev = NULL;
    
    if (g_timer_wheel[slot] != NULL) {
        g_timer_wheel[slot]->prev = client;
    }
    g_timer_wheel[slot] = client;
}

void timer_wheel_remove(Client* client) {
    if (client == NULL) return;
    
    // Standard doubly-linked list removal
    if (client->prev != NULL) {
        client->prev->next = client->next;
    } else {
        // This client was the *head* of its list
        // We must find its original slot
        int slot = (client->last_active_time + IDLE_TIMEOUT_SECONDS) % TIMER_WHEEL_SLOTS;
        // Check if it's still the head (it might have been removed already)
        if (g_timer_wheel[slot] == client) {
            g_timer_wheel[slot] = client->next;
        }
    }
    
    if (client->next != NULL) {
        client->next->prev = client->prev;
    }
    
    // Reset pointers for safety
    client->next = NULL;
    client->prev = NULL;
}

void reap_idle_clients(void) {
    // Find the current timer slot
    int slot = g_current_server_time % TIMER_WHEEL_SLOTS;
    
    // Get the list of clients who *should* be expired
    Client* node = g_timer_wheel[slot];
    g_timer_wheel[slot] = NULL; // Clear the slot
    
    // Walk the list and disconnect them all
    while (node != NULL) {
        Client* next = node->next; // Save next as handle disconnect will free the node
        
        // This check is a failsafe. A client might have been
        // reset and moved to a new slot, but our `remove` logic
        // failed.
        if (g_current_server_time - node->last_active_time >= IDLE_TIMEOUT_SECONDS) {
            printf("(Server) Client %d is idle. Disconnecting.\n", node->fd);
            write(node->fd, "(error) ERR idle timeout\n", 25);
            handle_client_disconnect(node); // This will free the node
        } else {
            // This client is not expired.
            // This is a "zombie" node from a previous slot.
            // We must re-add them to their *correct* new slot.
            // This fixes a subtle bug where a client's
            // timer is reset, but they aren't moved.
            timer_wheel_add(node);
        }
        
        node = next;
    }
}

void reap_ban_list(void) {
    // We can use a simple stack-allocated array.
    // At most, we could have MAX_CLIENTS bans.
    const char* keys_to_delete[MAX_CLIENTS];
    int delete_count = 0;

    HashMapIterator* iter = hashmap_iterator_create(g_ip_bans);
    if (iter == NULL) {
        perror("Failed to create ban list iterator");
        return;
    }

    HashMapEntry* entry;
    // Collect expired keys
    while ((entry = hashmap_iterator_next(iter)) != NULL) {
        time_t ban_expires = atol(entry->value); // string to long
        
        if (g_current_server_time >= ban_expires) {
            // Ban is expired. Mark it for deletion.
            if (delete_count < MAX_CLIENTS) {
                // We only store the pointer. This is safe because
                // the key is owned by the hashmap and won't be
                // freed until we call hashmap_delete.
                keys_to_delete[delete_count++] = entry->key;
            } else {
                // This would mean we have > 1024 bans.
                // We'll just stop collecting for this pass.
                break;
            }
        }
    }
    hashmap_iterator_free(iter);

    // Delete all the expired keys
    for (int i = 0; i < delete_count; i++) {
        hashmap_delete(g_ip_bans, keys_to_delete[i]);
    }
    
    if (delete_count > 0) {
        printf("(Server) Reaped %d expired IP bans.\n", delete_count);
    }
}
