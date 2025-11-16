CC = gcc
CFLAGS = -g -Wall -Wextra -std=gnu11 -Iinclude
TARGETS = test_hashmap test_parser

.PHONY: all clean check

all: $(TARGETS)

check: all
	@echo "\n--- Running Hashmap Tests with Valgrind ---"
	@valgrind --leak-check=full --show-leak-kinds=all ./test_hashmap
	@echo "\n--- Running Parser Tests (No Valgrind) ---"
	@./test_parser
	@echo "\n--- All Checks Complete ---"

test_hashmap: tests/test_hashmap.o src/hashmap.o
	$(CC) $(CFLAGS) -o $@ $^

test_parser: tests/test_parser.o src/parser.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGETS) src/*.o tests/*.o