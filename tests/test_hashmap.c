#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashmap.h"

int g_tests_run = 0;
int g_tests_failed = 0;

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            printf("  \x1B[31mFAIL:\x1B[0m (%s) at %s:%d\n", \
                   #condition, __FILE__, __LINE__); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define RUN_TEST(test_func) \
    do { \
        g_tests_run++; \
        printf("--- Running: %s ---\n", #test_func); \
        test_func(); \
    } while (0)



void test_basic_operations(void) {
    HashMap* map = hashmap_create();
    CHECK(map != NULL);

    int r = hashmap_set(map, "foo", "bar");
    CHECK(r == 0); 

    const char* val = hashmap_get(map, "foo");
    CHECK(val != NULL);
    CHECK(strcmp(val, "bar") == 0);
    printf("  PASSED: get/set single value\n");

    val = hashmap_get(map, "nonexistent");
    CHECK(val == NULL);
    printf("  PASSED: get non-existent key\n");

    hashmap_delete(map, "foo");
    
    val = hashmap_get(map, "foo");
    CHECK(val == NULL);
    printf("  PASSED: delete and get deleted key\n");

    hashmap_free(map);
}

void test_overwrite_value(void) {
    HashMap* map = hashmap_create();
    CHECK(map != NULL);

    hashmap_set(map, "key1", "value1");
    const char* val = hashmap_get(map, "key1");
    CHECK(strcmp(val, "value1") == 0);

    hashmap_set(map, "key1", "value_new");
    val = hashmap_get(map, "key1");
    CHECK(val != NULL);
    
    CHECK(strcmp(val, "value_new") == 0);
    printf("  PASSED: overwrite existing key\n");
    
    hashmap_set(map, "key2", "value2");
    val = hashmap_get(map, "key2");
    CHECK(strcmp(val, "value2") == 0);
    printf("  PASSED: other keys unaffected by overwrite\n");

    hashmap_free(map);
}

void test_null_handling(void) {
    HashMap* map = hashmap_create();
    CHECK(map != NULL);

    hashmap_free(NULL); 
    
    CHECK(hashmap_set(map, NULL, "value") == -1);
    CHECK(hashmap_set(map, "key", NULL) == -1);
    CHECK(hashmap_get(map, NULL) == NULL);
    hashmap_delete(map, NULL); 
    
    printf("  PASSED: NULL inputs handled gracefully\n");
    
    hashmap_free(map);
}

void test_resize_and_stress(void) {
    HashMap* map = hashmap_create();
    CHECK(map != NULL);

    const int num_items = 1000;
    
    char key_buf[100];
    char val_buf[100];

    printf("  Setting %d items (should trigger resize)...\n", num_items);
    for (int i = 0; i < num_items; i++) {
        sprintf(key_buf, "key-%d", i);
        sprintf(val_buf, "value-%d", i);
        
        int r = hashmap_set(map, key_buf, val_buf);
        CHECK(r == 0);
    }
    printf("  ...Set complete.\n");

    printf("  Verifying %d items...\n", num_items);
    for (int i = 0; i < num_items; i++) {
        sprintf(key_buf, "key-%d", i);
        sprintf(val_buf, "value-%d", i);

        const char* val = hashmap_get(map, key_buf);
        CHECK(val != NULL);
        
        CHECK(strcmp(val, val_buf) == 0);
    }
    printf("  ...Verification complete.\n");
    printf("  PASSED: resize and stress test\n");

    printf("  Deleting %d items...\n", num_items);
    for (int i = 0; i < num_items; i++) {
        sprintf(key_buf, "key-%d", i);
        hashmap_delete(map, key_buf);

        const char* val = hashmap_get(map, key_buf);
        CHECK(val == NULL);
    }
    printf("  ...Deletion complete.\n");
    printf("  PASSED: large-scale delete\n");

    hashmap_free(map);
}

int main(void) {
    printf("--- Running All Hash Map Tests ---\n\n");

    RUN_TEST(test_basic_operations);
    RUN_TEST(test_overwrite_value);
    RUN_TEST(test_null_handling);
    RUN_TEST(test_resize_and_stress);

    printf("\n--- Test Suite Complete ---\n");
    if (g_tests_failed > 0) {
        printf("  \x1B[31mRESULT: %d/%d tests FAILED.\x1B[0m\n", g_tests_failed, g_tests_run);
        return 1;
    } else {
        printf("  \x1B[32mRESULT: All %d tests PASSED.\x1B[0m\n", g_tests_run);
        return 0;
    }
}