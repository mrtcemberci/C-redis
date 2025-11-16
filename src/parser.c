#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"

typedef enum {
    STATE_START,  // We are in whitespace, looking for a new token
    STATE_IN_TOKEN,          // We are inside an unquoted token (like 'SET')
    STATE_IN_QUOTE           // We are inside a quoted token (like '"my key"')
} ParserState;

ParseResult parse_line(char* line, Command* cmd) {
    if (line == NULL || cmd == NULL) {
        return PARSE_ERROR_INVALID_INPUT;
    }

    cmd->argc = 0;
    ParserState state = STATE_START;
    char* token_start = NULL; // Pointer to the start of the current token

    // Preprocess to null terminate the line
    line[strcspn(line, "\r\n")] = '\0';

    for (char* p = line; ; p++) {
        char c = *p;

        switch (state) {
            case STATE_START:
                if (c == '\0') {
                    // End of the line
                    goto end_of_loop;
                }
                if (isspace(c)) {
                    // It's whitespace, just skip it and stay in this state
                    continue;
                }
                if (c == '"') {
                    // Start of a quoted token
                    state = STATE_IN_QUOTE;
                    token_start = p + 1; // The token starts *after* the quote
                } else {
                    // Start of a normal (unquoted) token
                    state = STATE_IN_TOKEN;
                    token_start = p;
                }
                break;

            case STATE_IN_TOKEN:
                if (c == '\0' || isspace(c)) {
                    // End of the unquoted token
                    if (c != '\0') {
                        *p = '\0'; // NUL-terminate the token inplace 
                    }
                    
                    if (cmd->argc >= MAX_COMMAND_ARGS) {
                        return PARSE_ERROR_TOO_MANY_ARGS;
                    }
                    cmd->argv[cmd->argc++] = token_start;
                    
                    state = STATE_START; // Go back to looking for a new token
                    
                    if (c == '\0') {
                        goto end_of_loop; // Line is done
                    }
                }
                // else: it's a normal char, stay in this state
                break;

            case STATE_IN_QUOTE:
                if (c == '\0') {
                    // ERROR: Line ended with an unclosed quote
                    return PARSE_ERROR_UNCLOSED_QUOTE;
                }
                if (c == '"') {
                    // End of the quoted token
                    *p = '\0'; // NUL-terminate the token inplace
                    
                    // Add the token to our argv
                    if (cmd->argc >= MAX_COMMAND_ARGS) {
                        return PARSE_ERROR_TOO_MANY_ARGS; // Too many arguments
                    }
                    cmd->argv[cmd->argc++] = token_start;

                    state = STATE_START; // Go back to looking for a new token
                }
                // else: it's a normal char or a space , stay in this state
                break;
        }

        if (c == '\0') {
            break;
        }
    }

end_of_loop:
    // Final check to see if we did not end in a quote
    if (state == STATE_IN_QUOTE) {
        return PARSE_ERROR_UNCLOSED_QUOTE; // Unclosed quote
    }

    return PARSE_SUCCESS; // Success
}