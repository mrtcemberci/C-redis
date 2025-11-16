#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

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

void print_command(Command* cmd) {
    printf("  argc = %d\n", cmd->argc);
    for (int i = 0; i < cmd->argc; i++) {
        printf("  argv[%d] = \"%s\"\n", i, cmd->argv[i]);
    }
}

void test_simple_command(void) {
    char line[] = "SET foo bar\n";
    Command cmd;
    ParseResult r = parse_line(line, &cmd);

    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd.argc == 3);
    CHECK(strcmp(cmd.argv[0], "SET") == 0);
    CHECK(strcmp(cmd.argv[1], "foo") == 0);
    CHECK(strcmp(cmd.argv[2], "bar") == 0);
}

void test_quoted_command(void) {
    char line[] = "SET \"my key\" \"my value with spaces\"\n";
    Command cmd;
    ParseResult r = parse_line(line, &cmd);

    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd.argc == 3);
    CHECK(strcmp(cmd.argv[0], "SET") == 0);
    CHECK(strcmp(cmd.argv[1], "my key") == 0);
    CHECK(strcmp(cmd.argv[2], "my value with spaces") == 0);
}

void test_edge_cases(void) {
    char line1[] = "   GET    foo   \n";
    Command cmd1;
    ParseResult r = parse_line(line1, &cmd1);
    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd1.argc == 2);
    CHECK(strcmp(cmd1.argv[0], "GET") == 0);
    CHECK(strcmp(cmd1.argv[1], "foo") == 0);

    char line2[] = "SET \"key\"value";
    Command cmd2;
    r = parse_line(line2, &cmd2);
    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd2.argc == 3);
    CHECK(strcmp(cmd2.argv[0], "SET") == 0);
    CHECK(strcmp(cmd2.argv[1], "key") == 0);
    CHECK(strcmp(cmd2.argv[2], "value") == 0);
    
    char line3[] = "GET foo";
    Command cmd3;
    r = parse_line(line3, &cmd3);
    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd3.argc == 2);
    CHECK(strcmp(cmd3.argv[0], "GET") == 0);
    CHECK(strcmp(cmd3.argv[1], "foo") == 0);
}

void test_empty_and_whitespace_lines(void) {
    char line1[] = "\n";
    Command cmd1;
    ParseResult r = parse_line(line1, &cmd1);
    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd1.argc == 0);
    
    char line2[] = "   \t   \r\n";
    Command cmd2;
    r = parse_line(line2, &cmd2);
    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd2.argc == 0);

    char line3[] = "";
    Command cmd3;
    r = parse_line(line3, &cmd3);
    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd3.argc == 0);
}

void test_mixed_tokens(void) {
    char line[] = "CMD \"arg1\" arg2 \"arg3 with space\" arg4";
    Command cmd;
    ParseResult r = parse_line(line, &cmd);

    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd.argc == 5);
    CHECK(strcmp(cmd.argv[0], "CMD") == 0);
    CHECK(strcmp(cmd.argv[1], "arg1") == 0);
    CHECK(strcmp(cmd.argv[2], "arg2") == 0);
    CHECK(strcmp(cmd.argv[3], "arg3 with space") == 0);
    CHECK(strcmp(cmd.argv[4], "arg4") == 0);
}

void test_empty_tokens(void) {
    char line[] = "SET \"\" \"\"";
    Command cmd;
    ParseResult r = parse_line(line, &cmd);

    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd.argc == 3);
    CHECK(strcmp(cmd.argv[0], "SET") == 0);
    CHECK(strcmp(cmd.argv[1], "") == 0);
    CHECK(strcmp(cmd.argv[2], "") == 0);
    
    char line2[] = "SET foo \"\" bar";
    Command cmd2;
    r = parse_line(line2, &cmd2);
    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd2.argc == 4);
    CHECK(strcmp(cmd2.argv[0], "SET") == 0);
    CHECK(strcmp(cmd2.argv[1], "foo") == 0);
    CHECK(strcmp(cmd2.argv[2], "") == 0);
    CHECK(strcmp(cmd2.argv[3], "bar") == 0);
}


void test_error_unclosed_quote(void) {
    char line[] = "SET \"my key \n";
    Command cmd;
    ParseResult r = parse_line(line, &cmd);
    CHECK(r == PARSE_ERROR_UNCLOSED_QUOTE);

    char line2[] = "SET \"another";
    r = parse_line(line2, &cmd);
    CHECK(r == PARSE_ERROR_UNCLOSED_QUOTE);
    
    char line3[] = "SET foo \"bar";
    r = parse_line(line3, &cmd);
    CHECK(r == PARSE_ERROR_UNCLOSED_QUOTE);
}

void test_error_too_many_args(void) {
    char line[1024];
    Command cmd;
    
    strcpy(line, "CMD");
    for (int i = 1; i < MAX_COMMAND_ARGS; i++) {
        strcat(line, " arg");
    }
    
    ParseResult r = parse_line(line, &cmd);
    CHECK(r == PARSE_SUCCESS);
    CHECK(cmd.argc == MAX_COMMAND_ARGS);

    strcpy(line, "CMD");
    for (int i = 1; i < MAX_COMMAND_ARGS + 1; i++) {
        strcat(line, " arg");
    }
    
    r = parse_line(line, &cmd);
    CHECK(r == PARSE_ERROR_TOO_MANY_ARGS);
}

int main(void) {
    printf("--- Running All Parser Tests ---\n\n");
    
    RUN_TEST(test_simple_command);
    RUN_TEST(test_quoted_command);
    RUN_TEST(test_edge_cases);
    RUN_TEST(test_empty_and_whitespace_lines);
    RUN_TEST(test_mixed_tokens);
    RUN_TEST(test_empty_tokens);
    RUN_TEST(test_error_unclosed_quote);
    RUN_TEST(test_error_too_many_args);

    printf("\n--- Test Suite Complete ---\n");
    if (g_tests_failed > 0) {
        printf("  \x1B[31mRESULT: %d/%d tests FAILED.\x1B[0m\n", g_tests_failed, g_tests_run);
        return 1;
    } else {
        printf("  \x1B[32mRESULT: All %d tests PASSED.\x1B[0m\n", g_tests_run);
        return 0;
    }
}