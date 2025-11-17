#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hashmap.h"

// A single node in a hash map bucket (to handle collisions)
typedef struct HashNode {
    char* key;
    char* value;
    struct HashNode* next;
} HashNode;

// The real HashMap struct, hidden only for hashmap.c
struct HashMap {
    HashNode** buckets;  // Array of pointers to HashNodes
    size_t capacity;     // How many buckets
    size_t count;        // How many items
};

struct HashMapIterator {
    HashMap* map;
    size_t current_bucket;
    HashNode* current_node;
    
    // We store the *last returned entry* here.
    // This avoids a malloc/free for every "next" call.
    HashMapEntry last_entry; 
};

HashMapIterator* hashmap_iterator_create(HashMap* map) {
    if (map == NULL) return NULL;
    
    HashMapIterator* iter = malloc(sizeof(HashMapIterator));
    if (iter == NULL) return NULL;
    
    iter->map = map;
    iter->current_bucket = 0;
    iter->current_node = NULL;
    
    return iter;
}

HashMapEntry* hashmap_iterator_next(HashMapIterator* iter) {
    if (iter == NULL) return NULL;

    //  Advance the current node in the linked list (if we're in one)
    if (iter->current_node != NULL) {
        iter->current_node = iter->current_node->next;
    }

    // If the list is done, find the next bucket
    while (iter->current_node == NULL) {
        //  Check if we've run out of buckets
        if (iter->current_bucket >= iter->map->capacity) {
            return NULL; // Iteration is finished
        }
        
        //  Get the head of the next bucket
        iter->current_node = iter->map->buckets[iter->current_bucket];
        
        //  Move to the next bucket index for the next time
        iter->current_bucket++;
        
        // If this bucket was empty, the while loop will repeat
        // and find the next non-empty bucket.
    }

    //  We have a valid node. Populate our static entry and return it.
    iter->last_entry.key = iter->current_node->key;
    iter->last_entry.value = iter->current_node->value;
    
    return &iter->last_entry;
}

void hashmap_iterator_free(HashMapIterator* iter) {
    free(iter); // Just free the iterator struct itself
}


/*
    Bucket array is a malloced heap array
    Bucket 0 -> Node1 -> Node2 -> etc...
    Bucket 1  All nodes are also malloced
    Bucket 2
    Bucket 3
*/

// A simple hash function (djb2)
static unsigned long hash(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

HashMap* hashmap_create(void) {
    HashMap* map = malloc(sizeof(*map));
    if (map == NULL) return NULL;
    map->capacity = DEFAULT_CAPACITY;
    map->count = 0;
    map->buckets = calloc(map->capacity, sizeof(*map->buckets));
    if (map->buckets == NULL) {
        free (map);
        return NULL;
    }
    return map;
}

void hashmap_free(HashMap* map) {
    if (map == NULL) return;

    for(size_t i = 0; i < map->capacity; i++) {
        HashNode* node = map->buckets[i];
        while (node != NULL) {
            HashNode* next = node->next;

            free(node->key);
            free(node->value);

            free(node);
            
            node = next;
        }
    }

    free(map->buckets);
    free(map);
}

static int hashmap_resize(HashMap* map) {
    if (map == NULL) {
        return -1;
    }

    size_t new_capacity = map->capacity * 2;
    if (new_capacity < map->capacity) {
        return -1; 
    }

    HashNode** new_buckets = calloc(new_capacity, sizeof(HashNode*));
    if (new_buckets == NULL) {
        return -1;
    }

    for (size_t i = 0; i < map->capacity; i++) {
        HashNode* node = map->buckets[i];

        while (node != NULL) {
            HashNode* next = node->next;

            size_t new_index = hash(node->key) % new_capacity;

            node->next = new_buckets[new_index]; /* Head will have this set to null */
            new_buckets[new_index] = node;

            node = next;
        }
    }

    free(map->buckets);
    map->buckets = new_buckets;
    map->capacity = new_capacity;

    return 0;
}
int hashmap_set(HashMap* map, const char* key, const char* value) {
    if (map == NULL || key == NULL || value == NULL) {
        return -1;
    }
    
    size_t index = hash(key) % map->capacity;

    HashNode* node = map->buckets[index];
    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            
            free(node->value);
            
            node->value = strdup(value); 
            
            if (node->value == NULL) {
                return -1; 
            }
            return 0;
        }
        node = node->next;
    }
    
    HashNode* new_node = malloc(sizeof(HashNode));
    if (new_node == NULL) {
        return -1; 
    }

    new_node->key = strdup(key);
    if (new_node->key == NULL) {
        free(new_node);
        return -1;
    }

    new_node->value = strdup(value);
    if (new_node->value == NULL) {
        free(new_node->key);
        free(new_node);
        return -1;
    }

    new_node->next = map->buckets[index];
    map->buckets[index] = new_node;

    map->count++;

    if (map->count > map->capacity * LOAD_FACTOR) {
        if (hashmap_resize(map) == -1) {
            return -1;
        }
    }

    return 0;
}

const char* hashmap_get(HashMap* map, const char* key) {
    if (map == NULL || key == NULL) {
        return NULL;
    }

    size_t index = hash(key) % map->capacity;

    HashNode* node = map->buckets[index];
    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            return node->value;
        }
        node = node->next;
    }

    return NULL;
}

void hashmap_delete(HashMap* map, const char* key) {
    if (map == NULL || key == NULL) {
        return;
    }

    size_t index = hash(key) % map->capacity;

    HashNode* node = map->buckets[index];
    HashNode* prev = NULL;

    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            
            if (prev == NULL) {

                map->buckets[index] = node->next;
            } else {

                prev->next = node->next;
            }

            free(node->key);
            free(node->value);
            free(node);

            map->count--;
            return;
        }

        prev = node;
        node = node->next;
    }
}