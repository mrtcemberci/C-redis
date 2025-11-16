CC = gcc
CFLAGS = -g -Wall -Wextra -std=gnu11 -Iinclude

TARGET = test_hashmap

SRCS = src/hashmap.c tests/test_hashmap.c

OBJS = $(SRCS:.c=.o)

.PHONY: all clean check

all: $(TARGET)

check: all
	@echo "--- Running Tests with Valgrind ---"
	@valgrind --leak-check=full --show-leak-kinds=all ./test_hashmap

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
