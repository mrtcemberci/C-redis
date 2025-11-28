#define _POSIX_C_SOURCE 199309L // Required for clock_gettime
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

// CONFIGURATION
#define NUM_THREADS 4
#define DURATION_SEC 5 
#define SERVER_PORT 6379
#define MAX_SAMPLES 2000000

// Thread structure to hold results AND config
typedef struct {
    // Stats
    long long requests_completed;
    int thread_id;
    long long* latencies;
    
    // Config
    int use_veth;           // Flag: 1 if using veth, 0 otherwise
    const char* server_ip;  // IP to connect to
} thread_stats_t;

// The worker function each thread runs
void *benchmark_worker(void *arg) {
    thread_stats_t *stats = (thread_stats_t *)arg;

    // Allocate memory for this thread's samples
    stats->latencies = malloc(sizeof(long long) * MAX_SAMPLES);
    if (!stats->latencies) {
        perror("Malloc failed");
        return NULL;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        free(stats->latencies);
        return NULL;
    }

    // CONDITIONAL BINDING: Only bind to 10.0.0.2 if in veth mode
    if (stats->use_veth) {
        struct sockaddr_in client_addr;
        client_addr.sin_family = AF_INET;
        client_addr.sin_port = 0; // Let the kernel choose an ephemeral port
        inet_pton(AF_INET, "10.0.0.2", &client_addr.sin_addr);

        if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            perror("Thread failed to bind to 10.0.0.2");
            free(stats->latencies);
            close(sock);
            return NULL;
        }
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    // Use the IP passed in the struct
    inet_pton(AF_INET, stats->server_ip, &serv_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        free(stats->latencies);
        close(sock);
        return NULL;
    }

    char *request = "SET foo bar\n"; 
    int req_len = strlen(request);
    char buffer[1024];

    struct timespec start, end;
    time_t loop_start = time(NULL);
    
    // Attack loop
    while (time(NULL) - loop_start < DURATION_SEC) {
        if (stats->requests_completed >= MAX_SAMPLES) break;

        clock_gettime(CLOCK_MONOTONIC, &start);

        if (send(sock, request, req_len, 0) < 0) break;
        if (recv(sock, buffer, sizeof(buffer), 0) <= 0) break;

        clock_gettime(CLOCK_MONOTONIC, &end);

        long long ns = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                       (end.tv_nsec - start.tv_nsec);
        
        stats->latencies[stats->requests_completed] = ns;
        stats->requests_completed++;
    }

    close(sock);
    return NULL;
}

/* For qsort */
int compare_ll(const void *a, const void *b) {
    long long arg1 = *(const long long *)a;
    long long arg2 = *(const long long *)b;
    return (arg1 > arg2) - (arg1 < arg2);
}

int main(int argc, char **argv) {
    // Check arguments
    int use_veth = 0;
    const char *target_ip = "127.0.0.1"; // Default to localhost

    if (argc > 1 && strcmp(argv[1], "veth") == 0) {
        use_veth = 1;
        target_ip = "10.0.0.1";
        printf("Mode: VETH (Binding to 10.0.0.2, Connecting to 10.0.0.1)\n");
    } else {
        printf("Mode: STANDARD (Localhost, no specific binding)\n");
    }

    pthread_t threads[NUM_THREADS];
    thread_stats_t stats[NUM_THREADS];
    struct timespec benchmark_start, benchmark_end;

    printf("Starting benchmark: %d threads for %d seconds...\n", NUM_THREADS, DURATION_SEC);

    clock_gettime(CLOCK_MONOTONIC, &benchmark_start);

    for (int i = 0; i < NUM_THREADS; i++) {
        stats[i].requests_completed = 0;
        stats[i].thread_id = i;
        // Pass configuration to workers
        stats[i].use_veth = use_veth;
        stats[i].server_ip = target_ip;
        
        pthread_create(&threads[i], NULL, benchmark_worker, &stats[i]);
    }

    long long total_reqs = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total_reqs += stats[i].requests_completed;
    }

    clock_gettime(CLOCK_MONOTONIC, &benchmark_end);

    double elapsed_seconds = (benchmark_end.tv_sec - benchmark_start.tv_sec) + 
                             (benchmark_end.tv_nsec - benchmark_start.tv_nsec) / 1e9;

    printf("\n--- THREAD STATS ---\n");
    // Aggregate all latencies
    long long *all_latencies = malloc(sizeof(long long) * total_reqs);
    if (!all_latencies && total_reqs > 0) {
        perror("Failed to allocate global latency buffer");
        return 1;
    }

    long long global_idx = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        printf("Thread %d completed %lld requests\n", stats[i].thread_id, stats[i].requests_completed);
        
        if (stats[i].requests_completed > 0) {
            memcpy(all_latencies + global_idx, 
                   stats[i].latencies, 
                   stats[i].requests_completed * sizeof(long long));
            global_idx += stats[i].requests_completed;
        }
        free(stats[i].latencies); // Cleanup thread memory immediately
    }

    // Sort for percentiles
    qsort(all_latencies, total_reqs, sizeof(long long), compare_ll);

    // Check if we actually have data before accessing the array
    if (total_reqs == 0) {
        printf("\nNo requests completed. Check server availability.\n");
        free(all_latencies);
        return 0; 
    }

    // Calculate Metrics
    double throughput = total_reqs / elapsed_seconds;
    long long p50 = all_latencies[(long long)(total_reqs * 0.50)];
    long long p99 = all_latencies[(long long)(total_reqs * 0.99)];
    long long p999 = all_latencies[(long long)(total_reqs * 0.999)];

    printf("\n--- RESULTS ---\n");
    printf("Actual Duration: %.4f seconds\n", elapsed_seconds);
    printf("Total Requests:  %lld\n", total_reqs);
    printf("Throughput:      %.2f requests/sec\n", throughput);
    
    printf("\n--- LATENCY (nanoseconds) ---\n");
    printf("P50 (Median):    %lld ns\n", p50);
    printf("P99 (Tail):      %lld ns\n", p99);
    printf("P99.9 (Deep):    %lld ns\n", p999);

    free(all_latencies);
    return 0;
}