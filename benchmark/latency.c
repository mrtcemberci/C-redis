#define _POSIX_C_SOURCE 199309L
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
#define DURATION_SEC 10
#define SERVER_PORT 6379
#define MAX_SAMPLES 2000000

// Target: 100,000 RPS Total (4 threads * 25,000)
#define TARGET_RPS_PER_THREAD 25000 

typedef struct {
    long long requests_completed;
    int thread_id;
    long long* latencies;
    int use_veth;           
    const char* server_ip;  
} thread_stats_t;

void *benchmark_worker(void *arg) {
    thread_stats_t *stats = (thread_stats_t *)arg;

    stats->latencies = malloc(sizeof(long long) * MAX_SAMPLES);
    if (!stats->latencies) { perror("Malloc failed"); return NULL; }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("Socket creation failed"); return NULL; }

    // VETH Binding Logic
    if (stats->use_veth) {
        struct sockaddr_in client_addr;
        client_addr.sin_family = AF_INET;
        client_addr.sin_port = 0;
        inet_pton(AF_INET, "10.0.0.2", &client_addr.sin_addr);

        if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            perror("Bind failed"); close(sock); return NULL;
        }
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, stats->server_ip, &serv_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed"); close(sock); return NULL;
    }

    char *request = "SET foo bar\n"; 
    int req_len = strlen(request);
    char buffer[1024];

    long long interval_ns = 1000000000LL / TARGET_RPS_PER_THREAD;
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    long long expected_start_ns = (long long)current_time.tv_sec * 1000000000LL + current_time.tv_nsec;

    time_t loop_start = time(NULL);
    
    while (time(NULL) - loop_start < DURATION_SEC) {
        if (stats->requests_completed >= MAX_SAMPLES) break;

        long long now_ns;
        // Busy-wait until schedule
        do {
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            now_ns = (long long)current_time.tv_sec * 1000000000LL + current_time.tv_nsec;
        } while (now_ns < expected_start_ns);

        if (send(sock, request, req_len, 0) < 0) break;
        if (recv(sock, buffer, sizeof(buffer), 0) <= 0) break;

        clock_gettime(CLOCK_MONOTONIC, &current_time);
        long long actual_end_ns = (long long)current_time.tv_sec * 1000000000LL + current_time.tv_nsec;

        // Corrected Latency (includes queue time)
        long long latency_ns = actual_end_ns - expected_start_ns;
        
        stats->latencies[stats->requests_completed] = latency_ns;
        stats->requests_completed++;

        expected_start_ns += interval_ns;
    }

    close(sock);
    return NULL;
}

int compare_ll(const void *a, const void *b) {
    long long arg1 = *(const long long *)a;
    long long arg2 = *(const long long *)b;
    return (arg1 > arg2) - (arg1 < arg2);
}

int main(int argc, char **argv) {
    int use_veth = 0;
    const char *target_ip = "127.0.0.1"; 

    if (argc > 1 && strcmp(argv[1], "veth") == 0) {
        use_veth = 1;
        target_ip = "10.0.0.1";
        printf("Mode: VETH (Binding to 10.0.0.2 -> 10.0.0.1)\n");
    } else {
        printf("Mode: STANDARD (Localhost)\n");
    }

    pthread_t threads[NUM_THREADS];
    thread_stats_t stats[NUM_THREADS];
    struct timespec b_start, b_end;

    printf("Starting LATENCY test (Fixed Schedule): %d threads, %d seconds...\n", NUM_THREADS, DURATION_SEC);
    printf("Target Schedule: %d RPS/thread (%d Total RPS)\n", TARGET_RPS_PER_THREAD, TARGET_RPS_PER_THREAD * NUM_THREADS);

    clock_gettime(CLOCK_MONOTONIC, &b_start);

    for (int i = 0; i < NUM_THREADS; i++) {
        stats[i].requests_completed = 0;
        stats[i].thread_id = i;
        stats[i].use_veth = use_veth;
        stats[i].server_ip = target_ip;
        pthread_create(&threads[i], NULL, benchmark_worker, &stats[i]);
    }

    long long total_reqs = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total_reqs += stats[i].requests_completed;
    }

    clock_gettime(CLOCK_MONOTONIC, &b_end);
    double elapsed = (b_end.tv_sec - b_start.tv_sec) + (b_end.tv_nsec - b_start.tv_nsec) / 1e9;
    
    long long *all_latencies = malloc(sizeof(long long) * total_reqs);
    long long global_idx = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        if (stats[i].requests_completed > 0) {
            memcpy(all_latencies + global_idx, stats[i].latencies, stats[i].requests_completed * sizeof(long long));
            global_idx += stats[i].requests_completed;
        }
        free(stats[i].latencies);
    }
    qsort(all_latencies, total_reqs, sizeof(long long), compare_ll);

    if (total_reqs == 0) return 1;

    printf("\n--- RESULTS (Latency @ 100k RPS) ---\n");
    printf("Throughput:      %.2f requests/sec\n", total_reqs / elapsed);
    printf("P50 Latency:     %lld ns\n", all_latencies[(long long)(total_reqs * 0.50)]);
    printf("P99 Latency:     %lld ns\n", all_latencies[(long long)(total_reqs * 0.99)]);
    printf("P99.9 Latency:   %lld ns\n", all_latencies[(long long)(total_reqs * 0.999)]);
    
    free(all_latencies);
    return 0;
}