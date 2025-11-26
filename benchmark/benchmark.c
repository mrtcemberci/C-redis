#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

// CONFIGURATION
#define NUM_THREADS 8
#define DURATION_SEC 10 // How long each thread spams the command for
#define SERVER_PORT 6379
#define SERVER_IP "127.0.0.1" // localhost..

// Thread structure to hold results
typedef struct {
    long long requests_completed;
    int thread_id;
} thread_stats_t;

// The worker function each thread runs
void *benchmark_worker(void *arg) {
    thread_stats_t *stats = (thread_stats_t *)arg;
    
    // Create a socket with the IPV4 protocol and TCP connection.
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    // Converts the IP address to store inside the struct
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return NULL;
    }

    // All threads spam the exact same request
    char *request = "SET foo bar\n"; 
    int req_len = strlen(request);
    char buffer[1024] = {0};

    // Timing setup
    time_t start_time = time(NULL);
    
    // Attack loop
    while (time(NULL) - start_time < DURATION_SEC) {

        send(sock, request, req_len, 0);
        
        // Blocks until buffer is written to by the server
        recv(sock, buffer, 1024, 0);
        
        stats->requests_completed++;
    }

    close(sock);
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    thread_stats_t stats[NUM_THREADS];

    printf("Starting benchmark: %d threads for %d seconds...\n", NUM_THREADS, DURATION_SEC);

    for (int i = 0; i < NUM_THREADS; i++) {
        stats[i].requests_completed = 0;
        stats[i].thread_id = i;
        pthread_create(&threads[i], NULL, benchmark_worker, &stats[i]);
    }

    long long total_reqs = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);

        // Print per-thread stats
        printf("Thread %d completed %lld requests\n",
               stats[i].thread_id,
               stats[i].requests_completed);

        total_reqs += stats[i].requests_completed;
    }

    double throughput = total_reqs / (double)DURATION_SEC;
    
    printf("\n--- RESULTS ---\n");
    printf("Total Requests: %lld\n", total_reqs);
    printf("Throughput:     %.2f requests/sec\n", throughput);

    return 0;
}
