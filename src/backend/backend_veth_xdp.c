#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Required for enabling advanced Linux extensions (mmap, huge pages, specific socket flags). */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <net/if.h>
#include <linux/if_packet.h> 
#include <linux/if_ether.h>  /* Defines Ethernet header constants (ETH_P_IP, ETH_ALEN). */
#include <linux/ip.h>        /* Defines the IP header structure (struct iphdr). */
#include <linux/tcp.h>       /* Defines the TCP header structure (struct tcphdr). */
#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h> 
#include <ctype.h> 
#include <sched.h>
#include <sys/ioctl.h>

#include "io_backend.h"
#include "client.h" 

/* * BACKEND_XDP (AF_PACKET V3 RX_RING + AF_INET RAW TX)
 * Robust Localhost Edition
 * ======================================================================================
 * RX (Receive): Uses AF_PACKET with a memory-mapped Ring Buffer. The kernel copies
 * packets directly into a shared memory region, avoiding the overhead of 'recv()' syscalls.
 * TX (Transmit): Uses AF_INET RAW sockets. We build the IP+TCP headers manually and
 * inject them.
 */

 /* The receiving RX Path is zero-copy fully and incredibly fast, however the sending TX path is not..
    For now it will remain this way. Maybe one day I can make it zero-copy if i get paid #quantlife */

#define LISTEN_PORT        6379 /* The port we sniff traffic on. */
#define FAKE_LISTENER_FD   99   /* Dummy FD to signal a new connection */
#define FAKE_FD_START      100  /* Fake FD Offset to prevent overlap with OS file descriptors */
#define MAX_XDP_SESSIONS   (MAX_CLIENTS - FAKE_FD_START)

/* * The Ring Buffer is a circular array in memory shared between Kernel and User.
 * BLOCK_SIZE: Size of one block in the ring (must be page aligned).
 * FRAME_SIZE: Size of one packet slot (must be large enough for MTU + headers).
 */
#define BLOCK_SIZE         (16 * 4096)
#define BLOCK_NR           2048
#define FRAME_SIZE         4096 
#define FRAME_NR           (BLOCK_SIZE * BLOCK_NR / FRAME_SIZE)

// Internal Buffers - 128KB to handle bursts
#define SESSION_BUF_SIZE   131072

/* Custom 8-bit TCP Flags */
/* Standard TCP control flags we will bitwise-OR into the TCP header. */
#define XDP_TCP_FIN  0x01
#define XDP_TCP_SYN  0x02
#define XDP_TCP_RST  0x04
#define XDP_TCP_PSH  0x08
#define XDP_TCP_ACK  0x10
#define XDP_TCP_URG  0x20

#define smp_wmb() __asm__ volatile("" ::: "memory")
/* PAUSE instruction to reduce CPU power/contention in spin-loops */
#define cpu_relax() __asm__ volatile("pause\n": : :"memory")

static int g_max_session_fd = FAKE_FD_START;

// Debug Macro
#define DLOG(...) fprintf(stderr, "[XDP] " __VA_ARGS__)

/* Micro-TCP Session State */
/* * Since we are the OS now, we must track the state of every connection.
 * This mimics the standard RFC 793 TCP State Machine.
 */
typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_RCVD,    /* Received SYN, sent SYN-ACK, waiting for ACK. */
    TCP_ESTABLISHED, /* Connection is live and data flows. */
    TCP_CLOSE_WAIT,  // Waiting for App to read EOF (Passive Close)
    TCP_LAST_ACK
} TcpState;

/*
 * The Session Structure.
 * This replaces the Kernel's "struct sock". It holds IP addresses, ports,
 * MAC addresses (needed for Ethernet framing), and Sequence/Ack numbers
 * to ensure reliability.
 */
typedef struct {
    int      id;            
    TcpState state;
    uint32_t src_ip;        /* Client's IP, also localhost */
    uint32_t dst_ip;        /* Our IP (Localhost) */
    uint16_t src_port;      /* Client's Port */
    uint16_t dst_port;      /* Our Port */
    
    unsigned char client_mac[ETH_ALEN]; /* We need to remember who sent the packet to reply correctly. */
    
    uint32_t seq_num;       // SND.NXT (Next sequence number we will send)
    uint32_t ack_num;       // RCV.NXT (Next sequence number we expect to receive)

    /* Timestamp and Window Scale options */
    uint32_t ts_recent;
    int ts_present;
    int client_wscale;
    
    /* A circular-ish buffer to hold payload data for the application layer. */
    char     rx_buf[SESSION_BUF_SIZE];
    size_t   rx_head;       // Read Ptr (App reads from here)
    size_t   rx_tail;       // Write Ptr (Network writes to here)

    size_t   rx_snapshot_len; /* The length of the block exposed to the server logic, prevents re-arm unseen data */
    /* ^ this did not exist before and I spent a whole day debugging very strange race conditions :( */

    int      active;        /* Is this slot in use? */
    int      accepted;      /* Has the upper layer 'accept()'ed this connection? */
} TcpSession;

static unsigned char g_src_mac[ETH_ALEN];
static TcpSession g_sessions[MAX_CLIENTS]; /* Global table of all active connections. */
static int        g_rx_fd = -1;  /* The AF_PACKET socket for Receiving. */
static int        g_tx_fd = -1; /* The AF_INET Raw socket for Sending. */
static char* g_ring_buffer = NULL;/* Pointer to the mmap'd shared memory region. */
static struct     iovec *g_ring_rd = NULL; /* Helper array to track where frames are in the ring. */
static int        g_ring_offset = 0; /* Current position in the ring buffer. */
static uint32_t   g_packet_count = 0; /* Counter for IP ID generation. */
static int g_ifindex = 0;

#define TX_BLOCK_SIZE      (4096)
#define TX_BLOCK_NR        256
#define TX_FRAME_SIZE      4096
#define TX_FRAME_NR        (TX_BLOCK_SIZE * TX_BLOCK_NR / TX_FRAME_SIZE)

static char *g_tx_ring_buffer = NULL;
static struct iovec *g_tx_ring_vec = NULL;
static int g_tx_ring_offset = 0;

static void handle_rx_packet(void *data, size_t len);

static inline uint32_t create_isn() {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    uint32_t isn = (uint32_t)ts.tv_sec ^ (uint32_t)ts.tv_nsec ^ (uint32_t)getpid();
    
    return isn;
}

/*
 * Standard Internet Checksum algorithm (RFC 1071).
 * Used for IP headers. We sum 16-bit words, carry the overflow, and flip bits.
 */
static inline uint16_t checksum(const void *data, int len) {
    const uint8_t *ptr = data;
    uint32_t sum = 0;
    
    // Sum 16-bit words
    while (len > 1) {
        // Read 2 bytes in native machine order
        uint16_t word = *(const uint16_t*)ptr;
        sum += word;
        ptr += 2;
        len -= 2;
    }
    
    // Handle the final odd byte (if length is odd)
    if (len > 0) {
        // The last byte is the MSB of the final 16-bit word (padded with 0)
        sum += *(const uint8_t *)ptr;
    }

    // Fold the 32-bit sum down to 16 bits
    // The loop handles multiple carries
    while (sum >> 16) { 
        sum = (sum & 0xFFFF) + (sum >> 16); 
    }
    
    // Return the one's complement
    return (uint16_t)~sum;
}
/*
 * TCP Checksum.
 * Unlike IP, TCP requires a "Pseudo Header" (SrcIP, DstIP, Protocol, Length)
 * to be included in the checksum calculation to verify packet integrity relative to IP.
 */
static inline uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, int len) {
    uint32_t sum = 0;
    
    // Source Address (4 bytes)
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    // Destination Address (4 bytes)
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    // Protocol (1 byte) + TCP Length (2 bytes) = 3 bytes, padded to 4.
    sum += htons(IPPROTO_TCP);
    sum += htons(len);

    // 2. Sum the entire TCP segment (TCP header + options + data)
    const uint16_t *ptr = (const uint16_t *)tcph;
    int remaining_len = len;

    while (remaining_len > 1) { 
        sum += *ptr++; 
        remaining_len -= 2; 
    }
    // Handle the final odd byte if present
    if (remaining_len > 0) { 
        sum += *(const uint8_t *)ptr; 
    }

    // Fold the 32-bit sum down to 16 bits
    while (sum >> 16) { 
        sum = (sum & 0xFFFF) + (sum >> 16); 
    }
    
    // Return the one's complement
    return (uint16_t)~sum;
}

/*
 * The Core I-O function, checks the ring buffer for packets marked USER
  processes in batches, uses pre-fetching to maximise throughput. 
  Calls handle_rx_packet and returns the slot back to the kernel in the MMAP
 */
#define FRAME_MASK (FRAME_NR - 1)
static inline void drain_rx_queue_internal(void) {
    const int BATCH = 512;  // Tune: 64–256 usually optimal
    int idx = g_ring_offset;

    struct tpacket_hdr *tp;
    char *frame;
    struct sockaddr_ll *sll;
    char *pdata;

    for (int i = 0; i < BATCH; i++) {
        tp = (struct tpacket_hdr *)g_ring_rd[idx].iov_base;

        __builtin_prefetch(g_ring_rd[(idx + 4) & FRAME_MASK].iov_base, 0, 1);
        __builtin_prefetch(g_ring_rd[(idx + 8) & FRAME_MASK].iov_base, 0, 1);

        // No new packets → stop immediately.
        if ((tp->tp_status & TP_STATUS_USER) == 0)
            break;

        frame = (char *)tp;
        sll   = (struct sockaddr_ll *)(frame + TPACKET_HDRLEN - sizeof(struct sockaddr_ll));
        pdata = frame + tp->tp_mac;

        // Skip our own outgoing packets, process incoming only.
        if (sll->sll_pkttype != PACKET_OUTGOING)
            handle_rx_packet(pdata, tp->tp_len);

        // Return this slot to the kernel, move forward
        tp->tp_status = TP_STATUS_KERNEL;
        /* Memory barrier to prevent CPU from going ahead without all memory operations before
        being complete  */
        __sync_synchronize();
        idx++;
        if (idx >= FRAME_NR)
            idx = 0;
    }

    g_ring_offset = idx;
}


/*
 * Another CORE I/O function
 * Constructs and transmits a raw packet
 * We manually build: Ethernet header -> IP Header -> TCP Header -> Options -> Payload.
 * Uses a TX ring and immediate flush for low-latency.
 */
static inline void send_raw_packet(char *payload, size_t len, TcpSession *s, uint8_t flags) {
    int idx = g_tx_ring_offset;
    volatile struct tpacket_hdr *tp = (struct tpacket_hdr *)g_tx_ring_vec[idx].iov_base;

    int next_idx = (idx + 1) % TX_FRAME_NR;
    /* Pre-fetch the next slot into the cache */
    __builtin_prefetch(g_tx_ring_vec[next_idx].iov_base, 1, 1);

    /* Spin-Wait for Ring Slot */
    int retries = 0;
    while (tp->tp_status != TP_STATUS_AVAILABLE && tp->tp_status != TP_STATUS_WRONG_FORMAT) {
        /* Optimization: Only kick kernel once every 32 spins to reduce lock contention */
        if ((retries & 31) == 0) {
            sendto(g_tx_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
        
        cpu_relax(); /* Pause instruction */
        
        if (++retries > 10000000) { 
            fprintf(stderr, "[FATAL] TX Ring Stuck! Interface down?\n");
            return; 
        }
    }

    /* Align the data start */
    uint8_t *frame_base = (uint8_t *)tp;
    uint8_t *data = frame_base + TPACKET_HDRLEN - sizeof(struct sockaddr_ll);
    
    /* Set up pointers */
    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr  *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    uint8_t *opt = (uint8_t *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    
    int opt_len = 0;

    if (flags & XDP_TCP_SYN) {
        opt[opt_len++] = 2; opt[opt_len++] = 4; 
        opt[opt_len++] = (1460 >> 8) & 0xFF; opt[opt_len++] = 1460 & 0xFF;
    }
    if (s->client_wscale > 0 && (flags & XDP_TCP_SYN)) { 
        opt[opt_len++] = 1; opt[opt_len++] = 3; opt[opt_len++] = 3; opt[opt_len++] = 0; 
    }
    if (s->ts_present) {
        while ((opt_len % 4) != 0) opt[opt_len++] = 1; 
        opt[opt_len++] = 8; opt[opt_len++] = 10;
        uint32_t my_time = htonl(s->ts_recent + 100);
        memcpy(opt + opt_len, &my_time, 4); opt_len += 4;
        uint32_t echo_time = htonl(s->ts_recent);
        memcpy(opt + opt_len, &echo_time, 4); opt_len += 4;
    }
    while ((opt_len % 4) != 0) opt[opt_len++] = 1; 

    /* Payload Copy */
    char *payload_dest = (char*)(opt + opt_len);
    if (len > 0) {
        memcpy(payload_dest, payload, len);
    }

    memcpy(eth->h_dest, s->client_mac, ETH_ALEN);
    memcpy(eth->h_source, g_src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + opt_len + len);
    iph->id = htons(g_packet_count++);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = s->src_ip; 
    iph->daddr = s->dst_ip; 
    iph->check = 0;
    iph->check = checksum(iph, sizeof(struct iphdr));

    tcph->source = s->src_port;
    tcph->dest   = s->dst_port;
    tcph->seq    = htonl(s->seq_num);
    tcph->ack_seq = htonl(s->ack_num);
    tcph->doff   = (sizeof(struct tcphdr) + opt_len) / 4;
    
    tcph->fin = (flags & XDP_TCP_FIN) ? 1 : 0;
    tcph->syn = (flags & XDP_TCP_SYN) ? 1 : 0;
    tcph->rst = (flags & XDP_TCP_RST) ? 1 : 0;
    tcph->psh = (flags & XDP_TCP_PSH) ? 1 : 0;
    tcph->ack = (flags & XDP_TCP_ACK) ? 1 : 0;
    tcph->urg = (flags & XDP_TCP_URG) ? 1 : 0;

    tcph->window = htons(64000);
    tcph->check  = 0; 
    tcph->urg_ptr = 0;

    int tcp_segment_len = sizeof(struct tcphdr) + opt_len + len;
    tcph->check = tcp_checksum(iph, tcph, tcp_segment_len);

    size_t total_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + opt_len + len;

    tp->tp_len = total_len;
    tp->tp_snaplen = total_len;
    smp_wmb();
    tp->tp_status = TP_STATUS_SEND_REQUEST;
    
    ssize_t sent = sendto(g_tx_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (sent < 0 && errno == ENOBUFS) {
        /* Congestion handling: do nothing, loop or poll will handle it, it is in the ring now anyway */
    }

    /* Advance Ring */
    g_tx_ring_offset = next_idx;

    /* Update Sequence */
    if (len > 0) s->seq_num += len;
    else if (flags & (XDP_TCP_SYN | XDP_TCP_FIN)) s->seq_num++;
}

/* Helper to find an existing session by Source IP/Port */
static TcpSession* get_session(uint32_t saddr, uint16_t sport) {
    for (int i=FAKE_FD_START; i<MAX_CLIENTS; i++) {
        if (g_sessions[i].active && 
            g_sessions[i].dst_ip == saddr && 
            g_sessions[i].dst_port == sport) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

/* Allocates a new session slot for a new connection. */
static TcpSession* create_session(uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, unsigned char* mac) {
    for (int i = FAKE_FD_START; i < MAX_CLIENTS; i++) {
        if (!g_sessions[i].active) {
            // Initialize cleanly
            memset(&g_sessions[i], 0, sizeof(TcpSession));
            g_sessions[i].active = 1;
            g_sessions[i].accepted = 0; 
            g_sessions[i].id = i; 
            g_sessions[i].state = TCP_LISTEN;
            g_sessions[i].dst_ip = saddr;
            g_sessions[i].src_ip = daddr;
            g_sessions[i].dst_port = sport; 
            g_sessions[i].src_port = dport; 
            // This is hard-coded in VETH pair but not hardcoding is fine
            // unsigned char static_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
            // memcpy(g_sessions[i].client_mac, static_mac, ETH_ALEN);
            memcpy(g_sessions[i].client_mac, mac, ETH_ALEN);
            g_sessions[i].seq_num = create_isn();   /* Initial Sequence Number (ISN) */
            g_sessions[i].rx_head = 0;
            g_sessions[i].rx_tail = 0;
            g_sessions[i].ts_present = 0;
            g_sessions[i].ts_recent = 0;
            g_sessions[i].client_wscale = 0;

            if (i > g_max_session_fd) g_max_session_fd = i;
            
            DLOG("New Session FD:%d Port:%d\n", i, ntohs(sport));
            return &g_sessions[i];
        }
    }
    //DLOG("Max sessions reached!\n");
    return NULL;
}

/* * MAIN PACKET PROCESSING ENGINE
 * This function is the "brain" of the TCP stack. It parses the raw bytes
 * and decides how to update state and what to send back.
 */
static void handle_rx_packet(void *data, size_t len) {
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) return;

    struct ethhdr *eth = (struct ethhdr *)data;
    if (ntohs(eth->h_proto) != ETH_P_IP) return; 

    struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    if (iph->protocol != IPPROTO_TCP) return; 

    struct tcphdr *tcph = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    
    if (ntohs(tcph->source) == LISTEN_PORT) return;
    if (ntohs(tcph->dest) != LISTEN_PORT) return;

    uint32_t ts_val = 0;
    int ts_found = 0;
    int wscale_found = 0;
    int wscale_val = 0;

    int tcp_hdr_len = tcph->doff * 4;
    int opts_len = tcp_hdr_len - sizeof(struct tcphdr);
    uint8_t *opt_ptr = (uint8_t *)tcph + sizeof(struct tcphdr);

    int i = 0;
    while (i < opts_len) {
        uint8_t kind = opt_ptr[i];
        if (kind == 0) break; // EOL
        if (kind == 1) { i++; continue; } // NOP
        
        if (i + 1 >= opts_len) break; // Safety
        uint8_t len = opt_ptr[i+1];
        if (len < 2 || i + len > opts_len) break; // Safety

        if (kind == 3 && len == 3) { // Window Scale
            wscale_val = opt_ptr[i+2];
            wscale_found = 1;
        } 
        else if (kind == 8 && len == 10) { // Timestamp
            // TS Value is the first 4 bytes of the value
            uint32_t *ts_ptr = (uint32_t*)(opt_ptr + i + 2);
            ts_val = ntohl(*ts_ptr);
            ts_found = 1;
        }
        i += len;
    }

    TcpSession *sess = get_session(iph->saddr, tcph->source);

    uint32_t seq = ntohl(tcph->seq);
    uint32_t ack_seq = ntohl(tcph->ack_seq);
    uint32_t seg_len = ntohs(iph->tot_len) - (iph->ihl*4) - (tcph->doff*4);

    if (tcph->syn && !tcph->ack) { 
        if (!sess) {
            sess = create_session(iph->saddr, tcph->source, iph->daddr, tcph->dest, eth->h_source);
            if (sess) {
                /* SAVE OPTIONS TO SESSION */
                sess->ts_present = ts_found;
                sess->ts_recent = ts_val;
                sess->client_wscale = wscale_found ? wscale_val : 0;
                
                sess->ack_num = seq + 1; 
                sess->state = TCP_SYN_RCVD;
                send_raw_packet(NULL, 0, sess, XDP_TCP_SYN | XDP_TCP_ACK);
            }
        } else {
            // RETRY Logic: Update Timestamp even on retry
            if (ts_found) sess->ts_recent = ts_val; 
            
            sess->ack_num = seq + 1;
            sess->seq_num = create_isn(); 
            sess->state = TCP_SYN_RCVD;
            sess->rx_head = sess->rx_tail = 0; 
            send_raw_packet(NULL, 0, sess, XDP_TCP_SYN | XDP_TCP_ACK);
        }
        return;
    }

    if (!sess) return;

    // UPDATE TIMESTAMP on every packet if present
    if (ts_found) sess->ts_recent = ts_val;

    uint32_t header_len = sizeof(struct ethhdr) + (iph->ihl*4) + (tcph->doff*4);
    if (len < header_len) return;
    
    if (tcph->ack) {
        if (sess->state == TCP_SYN_RCVD && !tcph->syn) {
            if (ack_seq == sess->seq_num) {
                sess->state = TCP_ESTABLISHED;
            }
        }
    }

    if (seg_len > 0) {
        if (seq == sess->ack_num) { 
            char *payload = (char*)data + header_len;
            size_t data_in_buffer = sess->rx_tail - sess->rx_head;
            size_t space = SESSION_BUF_SIZE - data_in_buffer;
            
            if (seg_len <= space) {
                size_t write_pos = sess->rx_tail % SESSION_BUF_SIZE;
                size_t till_end = SESSION_BUF_SIZE - write_pos;
                
                if (seg_len <= till_end) {
                    memcpy(sess->rx_buf + write_pos, payload, seg_len);
                } else {
                    memcpy(sess->rx_buf + write_pos, payload, till_end);
                    memcpy(sess->rx_buf, payload + till_end, seg_len - till_end);
                }
                
                sess->rx_tail += seg_len; 
                sess->ack_num = seq + seg_len; 
                
                // IMMEDIATE ACK
                //send_raw_packet(NULL, 0, sess, XDP_TCP_ACK);
            } 
        }
    }
    
    if (tcph->fin) {
        if (seq == sess->ack_num) { 
            sess->ack_num++; 
            send_raw_packet(NULL, 0, sess, XDP_TCP_ACK | XDP_TCP_FIN);
            sess->state = TCP_CLOSE_WAIT; 
        } else {
            send_raw_packet(NULL, 0, sess, XDP_TCP_ACK);
        }
    }
}

static int backend_init(void) {
    /* SETUP RX SOCKET (g_rx_fd)*/
    g_rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_rx_fd < 0) { perror("socket RX"); return -1; }

    /* Get Interface Index */
    g_ifindex = if_nametoindex("veth-host");
    if (g_ifindex == 0) { perror("if_nametoindex"); return -1; }

    /* Promiscuous Mode */
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = g_ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    setsockopt(g_rx_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    /* RX Ring Request */
    struct tpacket_req req_rx;
    memset(&req_rx, 0, sizeof(req_rx));
    req_rx.tp_block_size = BLOCK_SIZE;
    req_rx.tp_block_nr = BLOCK_NR;
    req_rx.tp_frame_size = FRAME_SIZE;
    req_rx.tp_frame_nr = FRAME_NR;

    if (setsockopt(g_rx_fd, SOL_PACKET, PACKET_RX_RING, &req_rx, sizeof(req_rx)) < 0) {
        perror("setsockopt RX_RING"); return -1;
    }

    /* Map RX Buffer */
    size_t rx_size = (size_t)req_rx.tp_block_nr * req_rx.tp_block_size;
    g_ring_buffer = mmap(NULL, rx_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_rx_fd, 0);
    if (g_ring_buffer == MAP_FAILED) { perror("mmap RX"); return -1; }

    /* Setup RX IO Vectors */
    g_ring_rd = malloc(req_rx.tp_frame_nr * sizeof(struct iovec));
    for (int i = 0; i < (int)req_rx.tp_frame_nr; i++) {
        g_ring_rd[i].iov_base = g_ring_buffer + (i * req_rx.tp_frame_size);
        g_ring_rd[i].iov_len = req_rx.tp_frame_size;
    }

    /* Bind RX Socket */
    struct sockaddr_ll sll_rx;
    memset(&sll_rx, 0, sizeof(sll_rx));
    sll_rx.sll_family = AF_PACKET;
    sll_rx.sll_protocol = htons(ETH_P_ALL);
    sll_rx.sll_ifindex = g_ifindex;
    if (bind(g_rx_fd, (struct sockaddr*)&sll_rx, sizeof(sll_rx)) < 0) {
        perror("bind RX"); return -1;
    }

    /*  SETUP TX SOCKET (g_tx_fd) */
    g_tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (g_tx_fd < 0) { perror("socket TX"); return -1; }

    /* TX Ring Request */
    struct tpacket_req req_tx;
    memset(&req_tx, 0, sizeof(req_tx));
    req_tx.tp_block_size = TX_BLOCK_SIZE;
    req_tx.tp_block_nr = TX_BLOCK_NR;
    req_tx.tp_frame_size = TX_FRAME_SIZE;
    req_tx.tp_frame_nr = TX_FRAME_NR;

    if (setsockopt(g_tx_fd, SOL_PACKET, PACKET_TX_RING, &req_tx, sizeof(req_tx)) < 0) {
        perror("setsockopt TX_RING"); return -1;
    }

    /* Map TX Buffer (Separate MMAP for separate FD) */
    size_t tx_size = (size_t)req_tx.tp_block_nr * req_tx.tp_block_size;
    g_tx_ring_buffer = mmap(NULL, tx_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_tx_fd, 0);
    if (g_tx_ring_buffer == MAP_FAILED) { perror("mmap TX"); return -1; }

    /* Setup TX IO Vectors */
    g_tx_ring_vec = malloc(req_tx.tp_frame_nr * sizeof(struct iovec));
    for (int i = 0; i < (int)req_tx.tp_frame_nr; i++) {
        g_tx_ring_vec[i].iov_base = g_tx_ring_buffer + (i * req_tx.tp_frame_size);
        g_tx_ring_vec[i].iov_len = req_tx.tp_frame_size;
    }

    /* Bind TX Socket */
    struct sockaddr_ll sll_tx;
    memset(&sll_tx, 0, sizeof(sll_tx));
    sll_tx.sll_family = AF_PACKET;
    sll_tx.sll_protocol = htons(ETH_P_IP);
    sll_tx.sll_ifindex = g_ifindex;
    if (bind(g_tx_fd, (struct sockaddr*)&sll_tx, sizeof(sll_tx)) < 0) {
        perror("bind TX"); return -1;
    }

    /* Retrieve MAC Address */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "veth-host", IFNAMSIZ - 1);
    if (ioctl(g_tx_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl MAC"); return -1;
    }
    memcpy(g_src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    
    printf("(Network) Backend 'xdp-veth' initialized (Dual Ring / Dual Socket Mode).\n");
    return 0;
}

/*
 * Main Polling Function.
 * This translates our custom Micro-TCP states into events the Server understands.
 */
static int backend_poll(IOEvent* events, int max_events, int timeout_ms) {
    (void)timeout_ms;
    // Always try to drain first
    /* Check for new packets from the network immediately. */
    drain_rx_queue_internal();

    int n = 0;
    
    // This reports new connections
    /* Scan session list for any connection that finished the Handshake but hasn't been Accept()'d. */
    for (int i=FAKE_FD_START; i<=g_max_session_fd; i++) {
        if (g_sessions[i].active && g_sessions[i].state == TCP_ESTABLISHED && !g_sessions[i].accepted) {
            IOEvent* ev = &events[n++];
            ev->fd = FAKE_LISTENER_FD; /* Tell server: "Event on Listener" */
            ev->events = IO_EVENT_READ;
            ev->result = g_sessions[i].id; /* Pass the new client's fake FD */
            g_sessions[i].accepted = 1;    /* Mark as pending accept */
            if (n >= max_events) return n;
        }
    }
    
    //  Report Data Available OR EOF
    /* Scan active sessions for data in their RX buffers or Close states. */
    for (int i = FAKE_FD_START; i <= g_max_session_fd; i++) {
        if (!g_sessions[i].active) continue;
        
        if (g_sessions[i].state == TCP_CLOSE_WAIT) {
            // Report EOF (0 bytes read)
            IOEvent* ev = &events[n++];
            ev->fd = g_sessions[i].id;
            ev->events = IO_EVENT_ERROR;
            ev->result = 0; /* Result 0 signifies EOF to the server logic */
            if (n >= max_events) return n;
        }
        else if (g_sessions[i].rx_head != g_sessions[i].rx_tail) {
            /* Data exists in buffer (Tail > Head) */
            IOEvent* ev = &events[n++];
            ev->fd = g_sessions[i].id;
            ev->events = IO_EVENT_READ;
            ev->result = g_sessions[i].rx_tail - g_sessions[i].rx_head; /* Bytes available */
            if (n >= max_events) return n;
        }
    }
    
    return n;
}

static int backend_socket_create_listener(int port) { (void)port; return FAKE_LISTENER_FD; }
static int backend_socket_accept(int listener_fd, char* ip_buf, size_t ip_buf_len) {
    (void)listener_fd;
    /* Find a session marked as "accepted=1" (by poll) and transition it to "accepted=2". */
    for (int i=FAKE_FD_START; i<= g_max_session_fd; i++) {
        if (g_sessions[i].active && g_sessions[i].state == TCP_ESTABLISHED && g_sessions[i].accepted == 1) {
            g_sessions[i].accepted = 2; // Consumed
            if (ip_buf) snprintf(ip_buf, ip_buf_len, "127.0.0.1");
            return g_sessions[i].id;
        }
    }
    errno = EAGAIN; return -1;
}
static void backend_socket_close(int fd) {
    if (fd >= FAKE_FD_START && fd < MAX_CLIENTS) {
        // If active, send FIN to be polite, or RST to be fast.
        // Benchmark expects FIN usually.
        TcpSession *s = &g_sessions[fd];
        if (s->active) {
            s->ack_num = 0; // Reset ACK? No.
            // send_raw_packet(NULL, 0, s, XDP_TCP_RST); // Fast kill
            // Or proper FIN:
            /* Send the FIN packet to the peer to close the TCP connection gracefully. */
            send_raw_packet(NULL, 0, s, XDP_TCP_FIN | XDP_TCP_ACK);
        }
        /* Reset the session slot so it can be reused. */
        g_sessions[fd].active = 0;
        g_sessions[fd].state = TCP_CLOSED;
        g_sessions[fd].accepted = 0;
        g_sessions[fd].rx_head = 0;
        g_sessions[fd].rx_tail = 0;

        /* Lazy reset for max_session_fd */
        if (fd == g_max_session_fd) {
            int new_max = FAKE_FD_START; 
            
            for (int i = fd - 1; i >= FAKE_FD_START; i--) {
                if (g_sessions[i].active) {
                    new_max = i;
                    break;
                }
            }
            g_max_session_fd = new_max;
        }
    }
}
/* These are no-ops because our custom stack handles state internally or doesn't support these specific ops. */
static int backend_watch_add(int fd, int events, void* user_data) { (void)fd; (void)events; (void)user_data; return 0; }
static int backend_watch_mod(int fd, int events, void* user_data) { (void)fd; (void)events; (void)user_data; return 0; }
static int backend_watch_del(int fd) { (void)fd; return 0; }
static int backend_make_nonblocking(int fd) { (void)fd; return 0; }

/* Does nothing (not used in async server ) */
static ssize_t backend_read(int fd, void* buf, size_t count) {
    (void)fd;
    (void)buf;
    (void)count;

    return 0;
}


/* Sends data by constructing PSH+ACK packets. */
static ssize_t backend_write(int fd, const void* buf, size_t count) {
    if (fd < FAKE_FD_START || fd >= MAX_CLIENTS) return -1;
    TcpSession *s = &g_sessions[fd];
    if (s->state == TCP_CLOSED) return -1;
    
    send_raw_packet((char*)buf, count, s, XDP_TCP_PSH | XDP_TCP_ACK);
    return count;
}


/* Tells the buf where the data is in the rx-ring by zero-copy principle */
static int backend_get_read_buffer(int fd, BackendBuffer* buf) {
    if (fd < 0 || fd >= MAX_CLIENTS) return -1;
    TcpSession *s = &g_sessions[fd];

    // Total bytes available is the difference between absolute pointers
    size_t avail = s->rx_tail - s->rx_head;

    if (avail == 0) {
        buf->data = NULL;
        buf->len = 0;
        buf->capacity = SESSION_BUF_SIZE;
        s->rx_snapshot_len = 0;
        return 0;
    }

    // Physical buffer position of the read head
    size_t read_pos = s->rx_head % SESSION_BUF_SIZE;

    // The maximum contiguous segment is from the head position to the end of the physical buffer
    size_t contiguous_len = SESSION_BUF_SIZE - read_pos;

    // The exposed length is the smaller of total available data or the contiguous segment
    size_t exposed_len = (avail < contiguous_len) ? avail : contiguous_len;

    s->rx_snapshot_len = exposed_len; // Snapshot the length of the contiguous segment
    
    buf->data = s->rx_buf + read_pos;
    buf->len = exposed_len;
    // Remaining free space in the whole buffer
    size_t data_in_buffer = s->rx_tail - s->rx_head;
    buf->capacity = SESSION_BUF_SIZE - data_in_buffer;

    return 0;
}


/* Finalizes zero-copy op and advanced the read pointer (head) */
static int backend_re_arm_read(int fd) {
    if (fd < 0 || fd >= MAX_CLIENTS) return -1;
    TcpSession *s = &g_sessions[fd];

    size_t to_consume = s->rx_snapshot_len;
    
    if (to_consume > 0) {
        // Simply advance the absolute head pointer
        s->rx_head += to_consume;
        s->rx_snapshot_len = 0;
    } else {
        s->rx_snapshot_len = 0;
    }

    return 0;
}


static ssize_t backend_submit_write(int fd, const void* buf, size_t count) {
    return backend_write(fd, buf, count);
}

IOBackend veth_backend = {
    .name = "xdp_veth",
    .is_async = 1, 
    .init = backend_init,
    .socket_create_listener = backend_socket_create_listener,
    .socket_accept = backend_socket_accept,
    .socket_close = backend_socket_close,
    .socket_make_nonblocking = backend_make_nonblocking,
    .watch_add = backend_watch_add,
    .watch_mod = backend_watch_mod,
    .watch_del = backend_watch_del,
    .poll = backend_poll,
    .read = backend_read,
    .write = backend_write,
    .get_read_buffer = backend_get_read_buffer,
    .re_arm_read = backend_re_arm_read,
    .submit_write = backend_submit_write
};