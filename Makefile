CC = gcc
CFLAGS = -g -Wall -Wextra -std=gnu11 -Iinclude

SERVER_EXE = redis-clone
SERVER_SRCS = src/server.c src/network.c src/client.c src/parser.c src/hashmap.c
SERVER_OBJS = $(SERVER_SRCS:.c=.o)

TEST_HASHMAP_EXE = test_hashmap
TEST_HASHMAP_SRCS = tests/test_hashmap.c src/hashmap.c
TEST_HASHMAP_OBJS = $(TEST_HASHMAP_SRCS:.c=.o)

TEST_PARSER_EXE = test_parser
TEST_PARSER_SRCS = tests/test_parser.c src/parser.c
TEST_PARSER_OBJS = $(TEST_PARSER_SRCS:.c=.o)


# Phony rule list
.PHONY: all clean check tests server-test

all: $(SERVER_EXE)

# "make tests" will build the unit test executables
tests: $(TEST_HASHMAP_EXE) $(TEST_PARSER_EXE)

# "make check" will build and run the unit tests
check: tests
	@echo "\n--- Running Unit Tests ---"
	@echo "\n--- [Unit] Running Hashmap Tests with Valgrind ---"
	@valgrind --leak-check=full --show-leak-kinds=all ./$(TEST_HASHMAP_EXE)
	@echo "\n--- [Unit] Running Parser Tests ---"
	@./$(TEST_PARSER_EXE)
	@echo "\n--- All Unit Tests Complete ---"

# "make server-test" will build the server and run ALL integration test scripts
server-test: $(SERVER_EXE)
	@echo "\n--- Running All Integration Tests ---"
	@# This loop finds every .sh file in tests/scripts and runs it
	@for test_script in tests/scripts/*.sh; do \
		echo "\n=== [Integration] Running: $$test_script ==="; \
		./$$test_script; \
	done
	@echo "\n--- All Integration Tests Complete ---"


$(SERVER_EXE): $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_HASHMAP_EXE): $(TEST_HASHMAP_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_PARSER_EXE): $(TEST_PARSER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# --- Generic rule to compile any .c file into a .o file ---
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# "make clean" - removes all build files and executables
clean:
	rm -f $(SERVER_EXE) $(TEST_HASHMAP_EXE) $(TEST_PARSER_EXE)
	rm -f src/*.o tests/*.o
	rm -f server.log
	rm -f tests/data/actual/*