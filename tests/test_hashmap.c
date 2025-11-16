#include <stdio.h>
#include <stdlib.h>
#include <string.h>   // For strcmp
#include <assert.h>   // For assert()

#include "hashmap.h"

/**
 * @brief Tests the most basic get/set/delete operations.
 */
void test_basic_operations(void) {
    printf("--- Running: %s ---\n", __FUNCTION__);

    HashMap* map = hashmap_create();
    assert(map != NULL);

    int r = hashmap_set(map, "foo", "bar");
    assert(r == 0); 

    const char* val = hashmap_get(map, "foo");
    assert(val != NULL);
    assert(strcmp(val, "bar") == 0);
    printf("  PASSED: get/set single value\n");

    val = hashmap_get(map, "nonexistent");
    assert(val == NULL);
    printf("  PASSED: get non-existent key\n");

    hashmap_delete(map, "foo");
    
    val = hashmap_get(map, "foo");
    assert(val == NULL);
    printf("  PASSED: delete and get deleted key\n");

    hashmap_free(map);
}

/**
 * @brief Tests that setting an existing key overwrites the old value.
 */
void test_overwrite_value(void) {
    printf("--- Running: %s ---\n", __FUNCTION__);

    HashMap* map = hashmap_create();
    assert(map != NULL);

    hashmap_set(map, "key1", "value1");
    const char* val = hashmap_get(map, "key1");
    assert(strcmp(val, "value1") == 0);

    hashmap_set(map, "key1", "value_new");
    val = hashmap_get(map, "key1");
    assert(val != NULL);
    
    assert(strcmp(val, "value_new") == 0);
    printf("  PASSED: overwrite existing key\n");
    
    hashmap_set(map, "key2", "value2");
    val = hashmap_get(map, "key2");
    assert(strcmp(val, "value2") == 0);
    printf("  PASSED: other keys unaffected by overwrite\n");

    hashmap_free(map);
}

/**
 * @brief Tests how the map handles NULL inputs.
 * These should not crash.
 */
void test_null_handling(void) {
    printf("--- Running: %s ---\n", __FUNCTION__);
    
    HashMap* map = hashmap_create();
    assert(map != NULL);

    hashmap_free(NULL); 
    
    assert(hashmap_set(map, NULL, "value") == -1);
    assert(hashmap_set(map, "key", NULL) == -1);
    assert(hashmap_get(map, NULL) == NULL);
    hashmap_delete(map, NULL); 
    
    printf("  PASSED: NULL inputs handled gracefully\n");
    
    hashmap_free(map);
}

/**
 * @brief Runs a stress test to force collisions and resizing.
 */
void test_resize_and_stress(void) {
    printf("--- Running: %s ---\n", __FUNCTION__);

    HashMap* map = hashmap_create();
    assert(map != NULL);

    const int num_items = 1000;
    
    char key_buf[100];
    char val_buf[100];

    printf("  Setting %d items (should trigger resize)...\n", num_items);
    for (int i = 0; i < num_items; i++) {
        sprintf(key_buf, "key-%d", i);
        sprintf(val_buf, "value-%d", i);
        
        int r = hashmap_set(map, key_buf, val_buf);
        assert(r == 0);
    }
    printf("  ...Set complete.\n");

    printf("  Verifying %d items...\n", num_items);
    for (int i = 0; i < num_items; i++) {
        sprintf(key_buf, "key-%d", i);
        sprintf(val_buf, "value-%d", i);

        const char* val = hashmap_get(map, key_buf);
        assert(val != NULL);
        
        assert(strcmp(val, val_buf) == 0);
    }
    printf("  ...Verification complete.\n");
    printf("  PASSED: resize and stress test\n");

    printf("  Deleting %d items...\n", num_items);
    for (int i = 0; i < num_items; i++) {
        sprintf(key_buf, "key-%d", i);
        hashmap_delete(map, key_buf);

        const char* val = hashmap_get(map, key_buf);
        assert(val == NULL);
    }
    printf("  ...Deletion complete.\n");
    printf("  PASSED: large-scale delete\n");

    hashmap_free(map);
}


int main(void) {
    printf("--- Running All Hash Map Tests ---\n\n");

    test_basic_operations();
    test_overwrite_value();
    test_null_handling();
    test_resize_and_stress();

    printf("\n--- All Tests Passed Successfully ---\n");
    return 0;
}