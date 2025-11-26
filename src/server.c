#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <strings.h> 
#include <stdint.h>
#include <stdbool.h>

#include "hashmap.h"
#include "parser.h"
#include "io_backend.h"
#include "client.h"

#define SERVER_PORT 6379
#define MAX_EVENTS 64
#define RESPONSE_BUFFER_SIZE 1024 

// Security rules
#define IDLE_TIMEOUT_SECONDS 5
#define TIMER_WHEEL_SLOTS (IDLE_TIMEOUT_SECONDS + 1) 
#define RATE_LIMIT_WINDOW_SECONDS 60
#define RATE_LIMIT_CONNECTIONS 100
#define BAN_DURATION_SECONDS 600

// The global database
HashMap* g_database = NULL;
HashMap* g_ip_counts = NULL;   
HashMap* g_ip_bans = NULL; 
time_t g_current_server_time = 0;
time_t g_last_ip_reap_time = 0; 
Client* g_timer_wheel[TIMER_WHEEL_SLOTS] = {0}; 

// Active Backend
IOBackend* g_backend = NULL;

bool g_is_async_mode = false;

void handle_new_connection(int listener_fd);
void handle_client_event(int client_fd);
void handle_client_disconnect(Client* client);
void handle_client_write(int client_fd);
void process_commands_in_buffer(Client* client);
void execute_command(Client* client, Command* cmd, ParseResult parse_status);
void handle_new_connection_async(const IOEvent* ev);

void timer_wheel_add(Client* client);
void timer_wheel_remove(Client* client);
void reap_idle_clients(void);

void reap_ban_list(void);


int main(int argc, char *argv[]) {
    // Default to Epoll
    g_backend = &epoll_backend;

    // Check command line arguments for backend selection
    if (argc > 1) {
        if (strcasecmp(argv[1], "io_uring") == 0) {
            g_backend = &iouring_backend;
        } else if (strcasecmp(argv[1], "epoll") == 0) {
            g_backend = &epoll_backend;
        } else if (strcasecmp(argv[1], "xdp") == 0) {
            g_backend = &xdp_backend;
        } else {
            fprintf(stderr, "Usage: %s [epoll|io_uring|xdp]\n", argv[0]);
            return 1;
        }
    }

    g_is_async_mode = (g_backend->is_async != 0);

    g_database = hashmap_create();
    g_ip_counts = hashmap_create();
    g_ip_bans = hashmap_create();
    
    if (g_database == NULL || g_ip_counts == NULL || g_ip_bans == NULL) {
        perror("Failed to create hashmaps");
        return 1;
    }
    
    // Initialise backend
    if (g_backend->init() < 0) {
        fprintf(stderr, "Failed to init network\n");
        return 1;
    }
    
    // Create the listening socket via backend
    int listener_fd = g_backend->socket_create_listener(SERVER_PORT);
    if (listener_fd < 0) {
        fprintf(stderr, "Failed to start listener\n");
        return 1;
    }

    IOEvent events[MAX_EVENTS];
    g_current_server_time = time(NULL);
    g_last_ip_reap_time = g_current_server_time;

    // Main event loop
    printf("--- Server is running ---\n");
    while (1) {
        g_current_server_time = time(NULL); 

        // Backend poll
        int n_ready = g_backend->poll(events, MAX_EVENTS, 1000);
        if (n_ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait failed");
            continue;
        }

        for (int i = 0; i < n_ready; i++) {
            IOEvent* ev = &events[i];
            int fd = (int)(intptr_t)ev->user_data;
            uint32_t e = ev->events;

            if (!g_is_async_mode) {
                /* Synchronous path (epoll) */
                if (fd == listener_fd) {
                    handle_new_connection(listener_fd);
                } else {
                    if (e & IO_EVENT_ERROR) {
                        printf("(Server) Error on socket fd %d\n", fd);
                        handle_client_disconnect(client_get(fd));
                        continue;
                    }
                    if (e & IO_EVENT_WRITE) {
                        handle_client_write(fd);
                    }
                    if (e & IO_EVENT_READ) {
                        handle_client_event(fd);
                    }
                }
            } else {
                /* Async path (io_uring-style) */
                int async_fd = ev->fd;
                uint32_t ae  = ev->events;

                if (async_fd == listener_fd && (ae & IO_EVENT_READ)) {
                    /* New connection: ev->result contains the actual client_fd */
                    handle_new_connection_async(ev);
                } else {
                    if (ae & IO_EVENT_ERROR) {
                        handle_client_disconnect(client_get(async_fd));
                        continue;
                    }

                    if (ae & IO_EVENT_WRITE) {
                        handle_client_write(async_fd);
                    }

                    if (ae & IO_EVENT_READ) {
                        handle_client_event(async_fd);
                    }
                }
            }
        }

        reap_idle_clients();

        if (g_current_server_time - g_last_ip_reap_time >= RATE_LIMIT_WINDOW_SECONDS) {
            printf("(Server) Tumbling rate-limit window. Resetting all IP counts.\n");
            hashmap_free(g_ip_counts);
            g_ip_counts = hashmap_create();
            g_last_ip_reap_time = g_current_server_time;
            reap_ban_list(); 
        }
    }

    hashmap_free(g_database);
    hashmap_free(g_ip_counts);
    hashmap_free(g_ip_bans);
    g_backend->socket_close(listener_fd);
    return 0;
}

void handle_new_connection_async(const IOEvent* ev) {
    int client_fd = (int)ev->result;  // result contains new client fd in async mode

    if (client_fd < 0) {
        fprintf(stderr, "(Server) Async accept error: %zd\n", ev->result);
        return;
    }

    if (client_fd >= MAX_CLIENTS) {
        fprintf(stderr, "Too many clients! Denying fd %d\n", client_fd);
        g_backend->socket_close(client_fd);
        return;
    }

    if (g_backend->socket_make_nonblocking(client_fd) < 0) {
        g_backend->socket_close(client_fd);
        return;
    }

    Client* new_client = client_create(client_fd);
    if (new_client == NULL) {
        fprintf(stderr, "Failed to create client for fd %d\n", client_fd);
        g_backend->socket_close(client_fd);
        return;
    }

    if (g_backend->watch_add(client_fd, IO_EVENT_READ, (void*)(intptr_t)client_fd) < 0) {
        client_free(new_client);
        return;
    }

    /* Arm the backend for a read operation for this FD */
    if (g_backend->re_arm_read(client_fd) < 0) {
        perror("re_arm_read (new async client)");
        handle_client_disconnect(new_client);
        return;
    }

    timer_wheel_add(new_client);
}


void handle_new_connection(int listener_fd) {
    while (1) {
        char client_ip[64]; // Buffer for IP
        
        // Accept new connection via backend
        int client_fd = g_backend->socket_accept(listener_fd, client_ip, sizeof(client_ip));

        if (client_fd < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                break; 
            }
            perror("accept");
            break; 
        }

        if (client_fd >= MAX_CLIENTS) {
            fprintf(stderr, "Too many clients! Denying fd %d\n", client_fd);
            g_backend->socket_close(client_fd);
            continue;
        }

        const char* ban_expiry_str = hashmap_get(g_ip_bans, client_ip);
        if (ban_expiry_str != NULL) {
            time_t ban_expires = atol(ban_expiry_str);
            if (g_current_server_time < ban_expires) {
                printf("(Server) Denied banned IP: %s\n", client_ip);
                g_backend->socket_close(client_fd);
                continue; 
            } else {
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
            printf("(Server) Banning IP for rate-limiting: %s\n", client_ip);
            
            time_t ban_expires = g_current_server_time + BAN_DURATION_SECONDS;
            char ban_expiry_str_buf[32];
            snprintf(ban_expiry_str_buf, 32, "%ld", ban_expires);
            
            hashmap_set(g_ip_bans, client_ip, ban_expiry_str_buf);
            
            hashmap_delete(g_ip_counts, client_ip);
            
            g_backend->socket_close(client_fd);
            continue;
        }

        char new_count_str[32];
        snprintf(new_count_str, 32, "%d", count);
        hashmap_set(g_ip_counts, client_ip, new_count_str);

        printf("(Server) Accepted connection from %s on fd %d\n", client_ip, client_fd);

        if (g_backend->socket_make_nonblocking(client_fd) < 0) {
            g_backend->socket_close(client_fd);
            continue; 
        }
        
        Client* new_client = client_create(client_fd);
        if (new_client == NULL) {
            fprintf(stderr, "Failed to create client for fd %d\n", client_fd);
            g_backend->socket_close(client_fd);
            continue;
        }

        // Add to backend: User data is the FD cast to void*
        if (g_backend->watch_add(client_fd, IO_EVENT_READ, (void*)(intptr_t)client_fd) < 0) {
            client_free(client_get(client_fd));
        }

        timer_wheel_add(new_client);
    }
}

void handle_client_event(int client_fd) {
    Client* client = client_get(client_fd);
    if (client == NULL) {
        return;
    }

    if (!g_is_async_mode) {
        ClientReadResult read_status = client_read_data(client);

        if (read_status == READ_DISCONNECTED || read_status == READ_ERROR) {
            handle_client_disconnect(client);
            return;
        }

        process_commands_in_buffer(client);
        return;
    }

    /* ASYNC PATH*/

    BackendBuffer buf;
    if (g_backend->get_read_buffer(client_fd, &buf) < 0) {
        return;
    }


    if (buf.len == 0) {
        return; // no data, not EOF here
    }

    /*
        This currently copies the backend buffer into the clients buffer,
        for a true zero-copy way we can just parse from the buffer directly.
        (TODO)
    */

    // Ensure client->read_buffer is large enough
    size_t needed = client->read_buffer_len + buf.len;
    if (needed > client->read_buffer_capacity) {
        size_t new_cap = client->read_buffer_capacity ? client->read_buffer_capacity : 1024;
        while (new_cap < needed) {
            new_cap *= 2;
        }

        char* new_buf = realloc(client->read_buffer, new_cap);
        if (!new_buf) {
            perror("realloc in async read");
            handle_client_disconnect(client);
            return;
        }
        client->read_buffer = new_buf;
        client->read_buffer_capacity = new_cap;
    }

    // Append new data
    memcpy(client->read_buffer + client->read_buffer_len, buf.data, buf.len);
    client->read_buffer_len += buf.len;

    // Parse commands from buffer (same as sync path)
    process_commands_in_buffer(client);

    /*
        This informs backend we are done with the data so arm the read
    */
    if (g_backend->re_arm_read(client_fd) < 0) {
        perror("re_arm_read failed");
        handle_client_disconnect(client);
        return;
    }
}

void process_commands_in_buffer(Client* client) {
    while (1) {
        char* newline = memchr(client->read_buffer, '\n', client->read_buffer_len);

        if (newline == NULL) {
            break;
        }

        size_t line_len = (newline - client->read_buffer);
        
        *newline = '\0';

        Command cmd;
        ParseResult parse_status = parse_line(client->read_buffer, &cmd);
        execute_command(client, &cmd, parse_status);

        size_t remaining_len = client->read_buffer_len - (line_len + 1);

        memmove(client->read_buffer, newline + 1, remaining_len);
        client->read_buffer_len = remaining_len;
    }
}

void execute_command(Client* client, Command* cmd, ParseResult parse_status) {
    char response_buffer[RESPONSE_BUFFER_SIZE];
    const char* response_msg = NULL; 

    if (parse_status != PARSE_SUCCESS) {
        if (parse_status == PARSE_ERROR_UNCLOSED_QUOTE) {
            response_msg = "(error) Protocol error: unclosed quote\n";
        } else if (parse_status == PARSE_ERROR_TOO_MANY_ARGS) {
            response_msg = "(error) Protocol error: too many arguments\n";
        } else {
            response_msg = "(error) Protocol error: invalid syntax\n";
        }
        printf("(Client %d) Parse Error: %s", client->fd, response_msg);
        goto queue_response; 
    }

    if (cmd->argc == 0) {
        timer_wheel_remove(client); 
        timer_wheel_add(client);
        return; 
    }
    
    if (strcasecmp(cmd->argv[0], "SET") == 0) {
        if (cmd->argc != 3) {
            response_msg = "(error) ERR wrong number of arguments for 'set' command\n";
            goto queue_response;
        }
        
        if (hashmap_set(g_database, cmd->argv[1], cmd->argv[2]) == 0) {
            //printf("(Client %d) EXEC: SET %s = ...\n", client->fd, cmd->argv[1]);
            response_msg = "OK\n";
        } else {
            response_msg = "(error) ERR failed to set key (OOM)\n";
        }
        goto reset_timer_and_queue;
    }

    if (strcasecmp(cmd->argv[0], "GET") == 0) {
        if (cmd->argc != 2) {
            response_msg = "(error) ERR wrong number of arguments for 'get' command\n";
            goto queue_response;
        }
        
        //printf("(Client %d) EXEC: GET %s\n", client->fd, cmd->argv[1]);
        const char* val = hashmap_get(g_database, cmd->argv[1]);
        
        if (val == NULL) {
            response_msg = "(nil)\n";
        } else {
            int len = snprintf(response_buffer, RESPONSE_BUFFER_SIZE, "\"%s\"\n", val);
            if (len < 0 || (size_t)len >= RESPONSE_BUFFER_SIZE) {
                response_msg = "(error) ERR value too large to send\n";
            } else {
                response_msg = response_buffer;
            }
        }
        goto reset_timer_and_queue;
    }
    
    if (strcasecmp(cmd->argv[0], "DEL") == 0) {
        if (cmd->argc != 2) {
            response_msg = "(error) ERR wrong number of arguments for 'del' command\n";
            goto queue_response;
        }
        
        //printf("(Client %d) EXEC: DEL %s\n", client->fd, cmd->argv[1]);
        hashmap_delete(g_database, cmd->argv[1]);
        response_msg = "(integer) 1\n";
        goto reset_timer_and_queue;
    }

    //printf("(Client %d) Unknown command: %s\n", client->fd, cmd->argv[0]);
    int len = snprintf(response_buffer, RESPONSE_BUFFER_SIZE, 
                       "(error) ERR unknown command '%s'\n", cmd->argv[0]);
    if (len > 0 && (size_t)len < RESPONSE_BUFFER_SIZE) {
        response_msg = response_buffer;
    } else {
        response_msg = "(error) ERR unknown command\n";
    }
    goto queue_response;


reset_timer_and_queue:
    timer_wheel_remove(client);
    timer_wheel_add(client);

queue_response:
    if (response_msg != NULL) {
        if (queue_client_response(client, response_msg) == -1) {
            printf("(Server) Client %d: OOM on write queue. Disconnecting.\n", client->fd);
            handle_client_disconnect(client);
            return;
        }
    }

    if (!g_is_async_mode) {
        /* Modifies the watching for this FD to be ready for a write event too */
        if (g_backend->watch_mod(client->fd,
                                 IO_EVENT_READ | IO_EVENT_WRITE,
                                 (void*)(intptr_t)client->fd) < 0) {
            perror("watch_mod (add WRITE) failed");
            handle_client_disconnect(client);
        }
    } else {
        size_t bytes_to_send = client->write_buffer_len - client->write_buffer_sent;

        if (bytes_to_send > 0) {
            char* data_start = client->write_buffer + client->write_buffer_sent;

            ssize_t submitted = g_backend->submit_write(client->fd,
                                                        data_start,
                                                        bytes_to_send);
            if (submitted < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Backend cannot take more now; rely on a WRITE event later
                    // or backend-internal queueing.
                    return;
                }
                perror("submit_write failed");
                handle_client_disconnect(client);
                return;
            }

            client->write_buffer_sent += (size_t)submitted;

            if (client->write_buffer_sent == client->write_buffer_len) {
                // All queued data considered "accepted"/sent.
                client->write_buffer_len = 0;
                client->write_buffer_sent = 0;
            }
        }

    }
}

void handle_client_write(int client_fd) {
    Client* client = client_get(client_fd);
    if (client == NULL) return;

    if (!g_is_async_mode) {

        size_t bytes_to_send = client->write_buffer_len - client->write_buffer_sent;
        if (bytes_to_send == 0) {
            goto stop_writing;
        }

        char* data_start = client->write_buffer + client->write_buffer_sent;

        ssize_t bytes_written = g_backend->write(client_fd, data_start, bytes_to_send);

        if (bytes_written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return; // Try again later
            }
            perror("write() failed");
            handle_client_disconnect(client);
            return;
        }

        client->write_buffer_sent += (size_t)bytes_written;

        if (client->write_buffer_sent == client->write_buffer_len) {
            client->write_buffer_len = 0;
            client->write_buffer_sent = 0;
        }

    stop_writing:
        if (g_backend->watch_mod(client_fd,
                                 IO_EVENT_READ,
                                 (void*)(intptr_t)client_fd) < 0) {
            perror("watch_mod (remove WRITE) failed");
            handle_client_disconnect(client);
        }
        return;
    }

    /*
     Assume that if the write is done we wrote everything for simplicity,
     in production we check how much is actually sent and queue the rest to go.
    */

    if (client->write_buffer_sent == client->write_buffer_len) {
        // nothing left to send; ensure the buffer is reset
        client->write_buffer_len = 0;
        client->write_buffer_sent = 0;
    }
    
    /* I commented this out because it may cause multiple re-arms, bad for efficiency. */

    // // Re-arm read so we can receive the next command
    // if (g_backend->re_arm_read(client_fd) < 0) {
    //     perror("re_arm_read after write completion failed");
    //     handle_client_disconnect(client);
    //     return;
    // }
}

void handle_client_disconnect(Client* client) {
    if (client == NULL) {
        return; 
    }
    
    printf("(Server) Client %d disconnected.\n", client->fd);
    timer_wheel_remove(client);

    g_backend->watch_del(client->fd);
    client_free(client); 
}

void timer_wheel_add(Client* client) {
    if (client == NULL) return;
    
    client->last_active_time = g_current_server_time;
    
    int slot = (client->last_active_time + IDLE_TIMEOUT_SECONDS) % TIMER_WHEEL_SLOTS;
    
    client->next = g_timer_wheel[slot];
    client->prev = NULL;
    
    if (g_timer_wheel[slot] != NULL) {
        g_timer_wheel[slot]->prev = client;
    }
    g_timer_wheel[slot] = client;
}

void timer_wheel_remove(Client* client) {
    if (client == NULL) return;
    
    if (client->prev != NULL) {
        client->prev->next = client->next;
    } else {
        int slot = (client->last_active_time + IDLE_TIMEOUT_SECONDS) % TIMER_WHEEL_SLOTS;
        if (g_timer_wheel[slot] == client) {
            g_timer_wheel[slot] = client->next;
        }
    }
    
    if (client->next != NULL) {
        client->next->prev = client->prev;
    }
    
    client->next = NULL;
    client->prev = NULL;
}

void reap_idle_clients(void) {
    int slot = g_current_server_time % TIMER_WHEEL_SLOTS;
    
    Client* node = g_timer_wheel[slot];
    g_timer_wheel[slot] = NULL; 
    
    while (node != NULL) {
        Client* next = node->next; 
        
        if (g_current_server_time - node->last_active_time >= IDLE_TIMEOUT_SECONDS) {
            printf("(Server) Client %d is idle. Disconnecting.\n", node->fd);
            // Writing exact string via backend
            g_backend->write(node->fd, "(error) ERR idle timeout\n", 25);
            handle_client_disconnect(node); 
        } else {
            timer_wheel_add(node);
        }
        
        node = next;
    }
}

void reap_ban_list(void) {
    const char* keys_to_delete[MAX_CLIENTS];
    int delete_count = 0;

    HashMapIterator* iter = hashmap_iterator_create(g_ip_bans);
    if (iter == NULL) {
        perror("Failed to create ban list iterator");
        return;
    }

    HashMapEntry* entry;
    while ((entry = hashmap_iterator_next(iter)) != NULL) {
        time_t ban_expires = atol(entry->value); 
        
        if (g_current_server_time >= ban_expires) {
            if (delete_count < MAX_CLIENTS) {
                keys_to_delete[delete_count++] = entry->key;
            } else {
                break;
            }
        }
    }
    hashmap_iterator_free(iter);

    for (int i = 0; i < delete_count; i++) {
        hashmap_delete(g_ip_bans, keys_to_delete[i]);
    }
    
    if (delete_count > 0) {
        printf("(Server) Reaped %d expired IP bans.\n", delete_count);
    }
}