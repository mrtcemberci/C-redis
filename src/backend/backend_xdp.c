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
#include <time.h>

#include "io_backend.h"
#include "client.h" 

/* 
 * BACKEND_XDP (AF_PACKET V3 RX_RING + AF_INET RAW TX)
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
    
    /* A circular-ish buffer to hold payload data for the application layer. */
    char     rx_buf[SESSION_BUF_SIZE];
    size_t   rx_head;       // Read Ptr (App reads from here)
    size_t   rx_tail;       // Write Ptr (Network writes to here)

    size_t   rx_snapshot_len; /* The length of the block exposed to the server logic, prevents re-arm unseen data */
    /* ^ this did not exist before and I spent a whole day debugging very strange race conditions :( */

    int      active;        /* Is this slot in use? */
    int      accepted;      /* Has the upper layer 'accept()'ed this connection? */

    uint32_t ts_recent;
    int ts_present;

    int client_wscale;
} TcpSession;

static TcpSession g_sessions[MAX_CLIENTS]; /* Global table of all active connections. */
static int        g_raw_fd = -1;  /* The AF_PACKET socket for Receiving. */
static int        g_send_fd = -1; /* The AF_INET Raw socket for Sending. */
static char* g_ring_buffer = NULL;/* Pointer to the mmap'd shared memory region. */
static struct     iovec *g_ring_rd = NULL; /* Helper array to track where frames are in the ring. */
static int        g_ring_offset = 0; /* Current position in the ring buffer. */
static uint32_t   g_packet_count = 0; /* Counter for IP ID generation. */
static int        g_ifindex = 0;

// Forward declarations
static void handle_rx_packet(void *data, size_t len);

static uint32_t create_isn(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    // Mix seconds and nanoseconds to create a rapidly changing 32-bit number
    return (uint32_t)(ts.tv_sec ^ ts.tv_nsec); 
}

/* * CORE CHECKSUM MATH
 * Sums 16-bit words from a buffer. Handles odd lengths by padding with zero.
 * Returns the raw 32-bit accumulated sum (no inversion).
 */
static inline uint32_t raw_checksum_sum(const void *data, int len) {
    const char *ptr = (const char *)data;
    uint32_t sum = 0;
    
    while (len > 1) {
        uint16_t val;
        memcpy(&val, ptr, 2); 
        sum += val;
        ptr += 2;
        len -= 2;
    }
    
    if (len > 0) {
        sum += *(const uint8_t *)ptr;
    }
    
    return sum;
}

/* * IP Checksum Wrapper 
 * folds the sum and inverts it.
 */
static inline uint16_t ip_checksum(const void *data, int len) {
    uint32_t sum = raw_checksum_sum(data, len);
    
    while (sum >> 16) { 
        sum = (sum & 0xFFFF) + (sum >> 16); 
    }
    return ~sum;
}

/* * TCP Checksum Wrapper
 * Manually constructs the Pseudo-Header in a buffer to guarantee byte order.
 */
static inline uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, int len) {
    uint32_t sum = 0;

    /* 1. Pseudo-Header (Constructed explicitly on stack) */
    struct {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t length;
    } __attribute__((packed)) pseudo;

    pseudo.src_ip = iph->saddr;
    pseudo.dst_ip = iph->daddr;
    pseudo.zero   = 0;
    pseudo.proto  = IPPROTO_TCP;
    pseudo.length = htons(len);

    /* Sum Pseudo-Header */
    sum += raw_checksum_sum(&pseudo, sizeof(pseudo));

    /* 2. Sum TCP Segment (Header + Options + Payload) */
    sum += raw_checksum_sum(tcph, len);

    /* 3. Fold to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

/* * SELF-VERIFICATION TOOL
 * Call this before sendto(). It calculates what the checksum SHOULD be 
 * and compares it to what is in the packet.
 */
static void verify_packet_integrity(struct iphdr *iph, struct tcphdr *tcph, int tcp_len) {
    // Verify IP
    uint16_t old_ip_check = iph->check;
    iph->check = 0; // Zero out to calculate
    uint16_t calc_ip = ip_checksum(iph, sizeof(struct iphdr));
    iph->check = old_ip_check; // Restore

    if (calc_ip != old_ip_check) {
        fprintf(stderr, "[CRITICAL FAIL] IP Checksum Mismatch! Calc: %04x, Pkt: %04x\n", calc_ip, old_ip_check);
    }

    // Verify TCP
    uint16_t old_tcp_check = tcph->check;
    tcph->check = 0; // Zero out to calculate
    uint16_t calc_tcp = tcp_checksum(iph, tcph, tcp_len);
    tcph->check = old_tcp_check; // Restore

    if (calc_tcp != old_tcp_check) {
        fprintf(stderr, "[CRITICAL FAIL] TCP Checksum Mismatch! Calc: %04x, Pkt: %04x\n", calc_tcp, old_tcp_check);
    } else {
        fprintf(stderr, "[DEBUG] Checksums Verified OK.\n");
    }
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
        idx++;
        if (idx >= FRAME_NR)
            idx = 0;
    }

    g_ring_offset = idx;
}


/*
 * Another CORE I/O function
 * Constructs and transmits a raw TCP/IP packet
 * We manually build: IP Header -> TCP Header -> Options -> Payload.
 */
static inline void send_raw_packet(char *payload, size_t len, TcpSession *s, uint8_t flags) {
    char frame[4096];
    memset(frame, 0, sizeof(frame));

    /* 1. Map structs: ETHERNET -> IP -> TCP -> Options -> Data */
    //struct ethhdr *eth = (struct ethhdr *)frame;
    // struct iphdr  *iph = (struct iphdr *)(frame + sizeof(struct ethhdr));
    // struct tcphdr *tcph = (struct tcphdr *)(frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    // uint8_t *opt = (uint8_t *)(frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct iphdr  *iph = (struct iphdr *)frame; // Now starts at the beginning
    struct tcphdr *tcph = (struct tcphdr *)(frame + sizeof(struct iphdr));
    uint8_t *opt = (uint8_t *)(frame + sizeof(struct iphdr) + sizeof(struct tcphdr));
    
    int opt_len = 0;
    if (flags & XDP_TCP_SYN) {
        opt[opt_len++] = 2; // Kind: MSS
        opt[opt_len++] = 4; // Len
        opt[opt_len++] = (1460 >> 8) & 0xFF; 
        opt[opt_len++] = 1460 & 0xFF;
    }

    if (s->client_wscale > 0) { 
        opt[opt_len++] = 1; // <--- NEW NOP HERE (Aligns this block to 4 bytes)   
        opt[opt_len++] = 3; // Kind: Window Scale
        opt[opt_len++] = 3; // Len
        opt[opt_len++] = 0; // Scale factor: 0
    }

    if (s->ts_present) {
        opt[opt_len++] = 1; // NOP
        opt[opt_len++] = 1; // NOP
        
        opt[opt_len++] = 8;  // Kind: Timestamp
        opt[opt_len++] = 10; // Len
        
        // PAWS Fix: echo + 100
        uint32_t my_time = htonl(s->ts_recent + 100);
        memcpy(opt + opt_len, &my_time, 4);
        opt_len += 4;
        
        // Echo
        uint32_t echo_time = htonl(s->ts_recent);
        memcpy(opt + opt_len, &echo_time, 4);
        opt_len += 4;
    }

    char *data = (char*)(opt + opt_len);

    /* 2. Fill ETHERNET Header (Layer 2) */
    /* On Loopback, MACs are ignored or 00s, but we must fill the struct. */
    // memcpy(eth->h_dest, s->client_mac, ETH_ALEN); // Send back to who sent to us
    // memset(eth->h_source, 0, ETH_ALEN);           // Source is us (lo is 00:00...)
    // eth->h_proto = htons(ETH_P_IP);               // Protocol is IP (0x0800)

    /* 3. Fill IP Header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    // Total len includes IP header, TCP header, Options, and Payload (NOT Ethernet header)
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + opt_len + len);
    iph->id = htons(g_packet_count++);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = s->src_ip; 
    iph->daddr = s->dst_ip; 
    iph->check = 0;
    iph->check = ip_checksum(iph, sizeof(struct iphdr));

    /* 4. Fill TCP Header */
    tcph->source = s->src_port;
    tcph->dest   = s->dst_port;
    
    uint32_t seq_before = s->seq_num;
    tcph->seq    = htonl(seq_before);
    tcph->ack_seq = htonl(s->ack_num);
    tcph->doff   = (sizeof(struct tcphdr) + opt_len) / 4;
    
    if (flags & XDP_TCP_FIN) tcph->fin = 1;
    if (flags & XDP_TCP_SYN) tcph->syn = 1;
    if (flags & XDP_TCP_RST) tcph->rst = 1;
    if (flags & XDP_TCP_PSH) tcph->psh = 1;
    if (flags & XDP_TCP_ACK) tcph->ack = 1;
    if (flags & XDP_TCP_URG) tcph->urg = 1;

    tcph->window = htons(64000);
    tcph->check  = 0; 
    tcph->urg_ptr = 0;

    if (len > 0) {
        memcpy(data, payload, len);
    }
    int tcp_segment_len = sizeof(struct tcphdr) + opt_len + len;

    /* TCP Checksum covers Pseudo-Header + TCP + Options + Data */
    tcph->check = 0;
    tcph->check = tcp_checksum(iph, tcph, tcp_segment_len);

    verify_packet_integrity(iph, tcph, tcp_segment_len);

    /* 5. Prepare SockAddr_LL (Link Layer Address) */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = g_ifindex; // Must match the loopback interface index
    sll.sll_halen = ETH_ALEN;
    sll.sll_protocol = htons(ETH_P_IP);
    memcpy(sll.sll_addr, s->client_mac, ETH_ALEN); 

    /* 6. Send raw frame */
    //size_t total_frame_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + opt_len + len;
    size_t total_frame_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + opt_len + len;


    ssize_t sent = -1;
    int retries = 0;
    
    while (1) { 
        /* Note: We send 'total_frame_len' which includes ethhdr */
        sent = sendto(g_send_fd, frame, total_frame_len, 
                      0, (struct sockaddr*)&sll, sizeof(sll));
        
        if (sent >= 0) break;
        
        if (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            drain_rx_queue_internal();
            if (retries < 1000) {
                retries++;
            } else {
                struct pollfd pfd = { .fd = g_send_fd, .events = POLLOUT };
                poll(&pfd, 1, 1); 
                retries = 0;
            }
            continue;
        }
        
        perror("sendto (AF_PACKET) fatal");
        break; 
    }
    
    if (sent >= 0) {
        if (len > 0) s->seq_num += len;
        else if (flags & (XDP_TCP_SYN | XDP_TCP_FIN)) s->seq_num++;
    }
}

/* Helper to find an existing session by Source IP/Port */
static TcpSession* get_session(uint32_t saddr, uint16_t sport) {
    for (int i=0; i<MAX_CLIENTS; i++) {
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
            g_sessions[i].dst_ip = saddr;   /* Swapped: Packet Src is Session Dst */
            g_sessions[i].src_ip = daddr;   /* Swapped: Packet Dst is Session Src */
            g_sessions[i].dst_port = sport; 
            g_sessions[i].src_port = dport; 
            memcpy(g_sessions[i].client_mac, mac, ETH_ALEN);
            g_sessions[i].seq_num = create_isn();
            g_sessions[i].rx_head = 0;
            g_sessions[i].rx_tail = 0;
            
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

    TcpSession *sess = get_session(iph->saddr, tcph->source);

    uint32_t seq = ntohl(tcph->seq);
    uint32_t ack_seq = ntohl(tcph->ack_seq);
    uint32_t seg_len = ntohs(iph->tot_len) - (iph->ihl*4) - (tcph->doff*4);

    // --- LOGIC MOVED/DUPLICATED HERE FOR NEW SESSIONS ---
    
    // SYN HANDLING
    if (tcph->syn && !tcph->ack) { 
        if (!sess) {
            sess = create_session(iph->saddr, tcph->source, iph->daddr, tcph->dest, eth->h_source);
        } else {
            // Reuse existing
            sess->ack_num = seq + 1;
            sess->seq_num = create_isn();
            sess->state = TCP_SYN_RCVD;
            sess->rx_head = sess->rx_tail = 0; 
        }

        if (sess) {
            /* [FIX] PARSE OPTIONS NOW, so the new session captures the TS */
            sess->ts_present = 0;
            sess->client_wscale = 0; // Reset this for safety
            uint8_t *opt_ptr = (uint8_t *)tcph + 20; 
            int opt_remaining = (tcph->doff * 4) - 20;

            while (opt_remaining > 0) {
                uint8_t kind = opt_ptr[0];
                if (kind == 0) break;
                if (kind == 1) { opt_ptr++; opt_remaining--; continue; }

                uint8_t len = opt_ptr[1];
                if (len > opt_remaining || len < 2) break;

                if (kind == 8 && len == 10) { 
                    uint32_t ts_val;
                    memcpy(&ts_val, opt_ptr + 2, 4);
                    sess->ts_recent = ntohl(ts_val); 
                    sess->ts_present = 1;
                }

                if (kind == 3 && len == 3) { // Window Scale Option
                    sess->client_wscale = opt_ptr[2];
                }
                opt_ptr += len;
                opt_remaining -= len;
            }

            // NOW send the SYN-ACK (which will now correctly include the TS echo)
            sess->ack_num = seq + 1; 
            sess->state = TCP_SYN_RCVD;
            send_raw_packet(NULL, 0, sess, XDP_TCP_SYN | XDP_TCP_ACK);
        }
        return;
    }

    if (!sess) return;

    /* [FIX] FOR ESTABLISHED SESSIONS, PARSE OPTIONS HERE TO UPDATE TS */
    // We also need to update TS on data packets to keep PAWS happy
    if (1) {
        uint8_t *opt_ptr = (uint8_t *)tcph + 20; 
        int opt_remaining = (tcph->doff * 4) - 20;

        while (opt_remaining > 0) {
            uint8_t kind = opt_ptr[0];
            if (kind == 0) break; 
            if (kind == 1) { opt_ptr++; opt_remaining--; continue; } 

            uint8_t len = opt_ptr[1];
            if (len > opt_remaining || len < 2) break; 

            if (kind == 8 && len == 10) { 
                uint32_t ts_val;
                memcpy(&ts_val, opt_ptr + 2, 4);
                sess->ts_recent = ntohl(ts_val); // Update timestamp!
                sess->ts_present = 1;
            }

            if (kind == 3 && len == 3) { // Window Scale Option
                sess->client_wscale = opt_ptr[2];
            }
            opt_ptr += len;
            opt_remaining -= len;
        }
    }

    uint32_t header_len = sizeof(struct ethhdr) + (iph->ihl*4) + (tcph->doff*4);
    if (len < header_len) return;
    
    // ACK HANDLING
    if (tcph->ack) {
        if (sess->state == TCP_SYN_RCVD && !tcph->syn) {
            if (ack_seq == 1001) {
                sess->state = TCP_ESTABLISHED;
            }
        }
    }

    // DATA Handling
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
            }
        }
    }
    
    // FIN HANDLING
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
    /* Create AF_PACKET socket for RX. This listens to Ethernet frames. */
    g_raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_raw_fd < 0) { perror("socket AF_PACKET RX"); return -1; }

/* 2. TX Socket (CHANGED from AF_INET to AF_PACKET) */
    /* We use SOCK_RAW so we can write the Ethernet header ourselves. */
    g_send_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (g_send_fd < 0) { perror("socket AF_PACKET TX"); return -1; }
    
    /* Set non-blocking to prevent freezes. */
    int flags = fcntl(g_send_fd, F_GETFL, 0);
    fcntl(g_send_fd, F_SETFL, flags | O_NONBLOCK);

    // HUGE BUFFERS
    /* Increase socket buffers to maximum to prevent packet drops during bursts. */
    int buf_size = 128 * 1024 * 1024; 
    setsockopt(g_send_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    setsockopt(g_raw_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

    /* Get Interface Index for Loopback ('lo'). */
    g_ifindex = if_nametoindex("lo");
    if (g_ifindex == 0) { perror("if_nametoindex lo"); return -1; }

    /* Enter Promiscuous mode to see all traffic on the interface. */
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = g_ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    setsockopt(g_raw_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    /* Prepare for Memory Mapped RX. */
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = BLOCK_SIZE;
    req.tp_block_nr = BLOCK_NR;
    req.tp_frame_size = FRAME_SIZE;
    req.tp_frame_nr = FRAME_NR;

    /* Tell the kernel to use the Ring Buffer for RX. */
    if (setsockopt(g_raw_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        perror("setsockopt PACKET_RX_RING"); return -1;
    }

    /* Map the ring buffer into our process memory space */
    size_t ring_size = (size_t)req.tp_block_nr * req.tp_block_size;
    g_ring_buffer = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_raw_fd, 0);
    if (g_ring_buffer == MAP_FAILED) { perror("mmap ring"); return -1; }

    /* Set up local IO Vector array to track frame positions easily. */
    g_ring_rd = malloc(req.tp_frame_nr * sizeof(struct iovec));
    for (int i = 0; i < (int)req.tp_frame_nr; i++) {
        g_ring_rd[i].iov_base = g_ring_buffer + (i * req.tp_frame_size);
        g_ring_rd[i].iov_len = req.tp_frame_size;
    }

    /* Bind the RX socket to the interface. */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = g_ifindex;

    if (bind(g_raw_fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind raw"); return -1;
    }
    
    printf("(Network) Backend 'xdp' (Robust) initialized on 'lo'.\n");
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
    for (int i=FAKE_FD_START; i<MAX_CLIENTS; i++) {
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
    for (int i = FAKE_FD_START; i < MAX_CLIENTS; i++) {
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
    for (int i=FAKE_FD_START; i<MAX_CLIENTS; i++) {
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

IOBackend xdp_backend = {
    .name = "xdp_bypass",
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