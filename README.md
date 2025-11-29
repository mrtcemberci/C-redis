# C-Redis (A Redis clone written in C)
A simple, high-performance, in-memory key-value store built in C.
Project was built to improve my skills and efficiency in low-level system programming, including:
- Kernel Bypass I/O: Implementing custom I/O stacks (e.g., XDP/Raw Sockets) for extreme speed.
- High-performance asynchronous I/O, with tools like epoll and io_uring
- Robust, stateful client management
- Advanced C data structures and memory management
- Server security and DoS attack mitigation

# Core Architecture
-Pluggable Network Backend: Includes production-ready implementations for:
  - epoll (Standard Linux high-performance I/O).
  - io_uring (Kernel's advanced asynchronous interface).
  - XDP-Lite / AF_PACKET v3: A custom user-space TCP stack leveraging memory-mapped RX ring buffer for zero-copy reading and kernel bypass for maximum throughput. Does not have a ring buffer for TX.
  - VETH / XDP-LITE-PREMIUM: Follows the same as XDP-Lite but has a TX write ring and more optimisations. 
- Fully Asynchronous I/O: Uses Edge-Triggered notification for both reads and writes.
- Custom Key-Value Store: A from-scratch, resizing HashMap built with separate-chaining, proven Valgrind-clean for zero memory leaks. Also features a custom iterator API.
- Robust State-Machine Parser: A hand-written parser for a text protocol with full quote-support (e.g., SET "my key" "my value").
- Dynamic Client Buffers: Client read (realloc) and write (queue_client_response) buffers are fully dynamic, handling partial/streamed network data and large responses without blocking.

# Benchmark
- I conducted comprehensive performance testing, focusing on the massive impact of low-level I/O and protocol optimization, particularly comparing the different backends on Loopback vs VETH setup.
- To run the benchmarks start the server following the guide below, run **cd benchmark/** and **make** This outputs two executable files, latency and throughput. You can configure the macros inside both throughput.c and latency.c, you can run the tests with **sudo taskset -c {cores} ./{benchmark}** for the normal loopback/localhost backends.
- To run the benchmark on the VETH backend you must run the script **veth-setup** inside **setup-scripts/**,
this creates the VETH environment, which you can then run the benchmark via **sudo ip netns exec clientns taskset -c {cores} ./{benchmark} veth**
- The latency test is designed to compensate for coordinated omission, which is a bias that occurs when slow-running serverices are less likely to be sampled by the benchmark client.
- Here are some stats from when I ran the benchmarks.
| Metric | XDP-VETH | XDP-LITE (Localhost/loopback) | EPOLL (Localhost) | IO_URING (Localhost) |
| :--- | :--- | :--- | :--- | :--- |
| **Max Throughput (RPS)** | **490,982** | 410,618 | 356,482 | 214,383 |
| **P50 Latency @ 100k RPS** | **4,642 ns** | 5,681 ns | 7,552 ns | 11,686 ns |
| **P99 Latency @ 100k RPS** | **6,189 ns** | 8,659 ns | 9,579 ns | 1,914,799 ns |
| **P99.9 Latency @ 100k RPS** | **6,628 ns** | 35,808 ns | 11,678 ns | 2,526,099 ns |
-- IO_URING has suspicious results.... Fix coming soon.

# Server Hardening & Security
- The server is hardened against common Denial of Service (DoS) attacks
- O(1) Idle Client Eviction: Implements a Timer Wheel to reap idle clients in constant time
- Buffer Overflow Protection: Enforces a MAX_CLIENT_BUFFER_SIZE on all client buffers, preventing a single client from causing an Out-of-Memory (OOM) crash via a large command.
- IP-Based Rate Limiting: Implements a Tumbling Window counter to track connection frequency. Abusive IPs are automatically added to a HashMap-based ban list, preventing "reconnection spam."

# Build
- Compiled via Makefile.
- **make** or **make all**: Builds the final redis-clone server executable.
- **make tests**: Builds the unit test executables.
- **make check**: Runs all Unit Tests:
  test_hashmap: A Valgrind-powered test for the hash map, including a 1000-item resize stress test.
  test_parser: A comprehensive test for the command parser's state machine.
- **make server-test**: Runs the full Automated Integration Suite. This builds the server and runs all scripts in tests/scripts/ to test live server behavior, including:
   - test_integration.sh (Happy path GET/SET/DEL)
   - test_boverflow.sh (Buffer overflow DoS test)
   - test_idle.sh (Idle client timeout test)
   - test_rate.sh (IP ban and rate-limit test)
   - Note: These tests require certain constant values such as ban time and idle time to work properly.
- **make clean**: Cleans all executables, object files, and test artifacts.

# How to run
- Once compiled by **make**, run ./redis-clone [epoll|io_uring|xdp|veth] (defaults to epoll)
- The server starts to listen on port 6379
- to run the backend **VETH|XDP** you must run the **xdp-setup** and **xdp-reset** scripts inside **setup-scripts/** when starting and done.
- to run the backend **VETH** you must also run the **veth-setup** script inside **setup-scripts/**
- You can try connecting as a client via 'netcat localhost 6379' on non-veth backends.
- YOu can try connecting as a client via 'sudo ip netns exec clientns nc 10.0.0.1 6379' on VETH backend.
- You can disconnect user-side by CTRL+C
- You can close the server by CTRL+C
- Logs are printed to the console for join events etc.
