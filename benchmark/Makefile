CC = gcc
CFLAGS = -Wall -Werror -g
LDFLAGS = -pthread
TARGET = benchmark
SRC = benchmark.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(TARGET)
	rm -f *.o

.PHONY: run
run: $(TARGET)
	./$(TARGET)