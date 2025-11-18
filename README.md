# C-Redis (A Redis clone written in C)
A simple, high-performance, in-memory key-value store built in C.
Project was built to improve my skills and efficiency in low-level system programming, including:
- High-performance asynchronous I/O with epoll
- Robust, stateful client management
- Advanced C data structures and memory management
- Server security and DoS attack mitigation

# Core Architecture
- Pluggable Network Backend: Features a v-table based IOBackend abstraction (include/io_backend.h), allowing the event loop to be swapped at runtime. Includes implementations for epoll (default) and io_uring (using submission queues). New backends can be implemented by defining a new IOBackend struct.
- Fully Asynchronous I/O: Uses Edge-Triggered notification for both reads and writes.
- Custom Key-Value Store: A from-scratch, resizing HashMap built with separate-chaining, proven Valgrind-clean for zero memory leaks. Also features a custom iterator API.
- Robust State-Machine Parser: A hand-written parser for a text protocol with full quote-support (e.g., SET "my key" "my value").
- Dynamic Client Buffers: Client read (realloc) and write (queue_client_response) buffers are fully dynamic, handling partial/streamed network data and large responses without blocking.

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
- Once compiled by **make**, run ./redis-clone [epoll|io_uring] (defaults to epoll)
- The server starts to listen on port 6379
- You can try connecting as a client via 'netcat localhost 6379'
- You can disconnect user-side by CTRL+C
- You can close the server by CTRL+C
- Logs are printed to the console
