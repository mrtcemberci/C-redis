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

# "make tests" will build the test executables
tests: $(TEST_HASHMAP_EXE) $(TEST_PARSER_EXE)

# "make check" will build tests, then run them
check: tests
	@echo "\n--- Running Hashmap Tests with Valgrind ---"
	@valgrind --leak-check=full --show-leak-kinds=all ./$(TEST_HASHMAP_EXE)
	@echo "\n--- Running Parser Tests ---"
	@./$(TEST_PARSER_EXE)
	@echo "\n--- All Checks Complete ---"

# make server-test will build the server and run the integration script
server-test: $(SERVER_EXE)
	@echo "\n--- Running Integration Test Script ---"
	@./test_integration.sh


$(SERVER_EXE): $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_HASHMAP_EXE): $(TEST_HASHMAP_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_PARSER_EXE): $(TEST_PARSER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SERVER_EXE) $(TEST_HASHMAP_EXE) $(TEST_PARSER_EXE) src/*.o tests/*.o