#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>

// The maximum number of arguments we'll parse in one command
#define MAX_COMMAND_ARGS 16

/**
 * @brief Defines the possible return codes from the parser.
 */
typedef enum {
    PARSE_SUCCESS = 0,
    PARSE_ERROR_INVALID_INPUT = -1,  // e.g., NULL pointers
    PARSE_ERROR_UNCLOSED_QUOTE = -2, // e.g., SET "foo
    PARSE_ERROR_TOO_MANY_ARGS = -3   // e.g., > MAX_COMMAND_ARGS
} ParseResult;


typedef struct Command {
    int argc;
    char* argv[MAX_COMMAND_ARGS];
} Command;

ParseResult parse_line(char* line, Command* cmd);

#endif // PARSER_H