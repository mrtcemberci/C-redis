#ifndef HASHMAP_H
#define HASHMAP_H

#include <stddef.h>

#define DEFAULT_CAPACITY 8

#define LOAD_FACTOR 0.7

typedef struct HashMap HashMap;

// Create a new hash map
HashMap* hashmap_create(void);

// Free a hash map
void hashmap_free(HashMap* map);

// Set a value for a key
// Returns 0 on success, -1 on failure
int hashmap_set(HashMap* map, const char* key, const char* value);

// Get a value for a key
// Returns the value, or NULL if not found
const char* hashmap_get(HashMap* map, const char* key);

// Delete a key
void hashmap_delete(HashMap* map, const char* key);

#endif // HASHMAP_H