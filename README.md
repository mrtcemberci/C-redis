# C-Redis (A Redis clone written in C)

A simple, high-performance, in-memory key-value store built in C.
Project was built to improve my skills and efficiency in low-level system programming, including:
- System calls with epoll
- Working with sockets
- Client management
- Robust parsing
- Memory safety

# Features
- GET, SET, DEL commands
- Quote support for key value pairs
- Non blocking: Uses epoll to manage all client connections async in a single thread
- Dynamic client buffers: Grows dynamically via realloc to handle large commands

# Build
- Compiled via makefile
- Build the server via 'make' / 'make all'
- Build the tests via 'make tests'
- Run the unit tests for the hashmap and parser via 'make check'
- Run the integration test via 'make server-test'
- Clean build files via 'make clean'

# How to run
- Once compiled by make, run ./redis-clone
- The server starts to listen on port 6379
- You can try connecting as a client via 'netcat localhost 6379'
- You can disconnect user-side by CTRL+C
- You can close the server by CTRL+C
