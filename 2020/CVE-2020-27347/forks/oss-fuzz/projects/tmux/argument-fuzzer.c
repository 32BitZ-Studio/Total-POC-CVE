#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "tmux.h"

#define FUZZER_MAXLEN 1024
#define MAX_ARG_LEN 32

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > FUZZER_MAXLEN) return 0;

    int args = data[0] % 16 + 1;
    data++;
    size--;

    if (size < (size_t)(args * MAX_ARG_LEN)) return 0;

    char **argv = (char **)malloc(sizeof(char *) * args);
    if (!argv) return 0;

    for (int i = 0; i < args; i++) {
        argv[i] = (char *)malloc(MAX_ARG_LEN);
        if (!argv[i]) {
            // Cleanup on failure
            for (int j = 0; j < i; j++) free(argv[j]);
            free(argv);
            return 0;
        }

        size_t copy_len = (size < MAX_ARG_LEN - 1) ? size : MAX_ARG_LEN - 1;
        memcpy(argv[i], data, copy_len);
        argv[i][copy_len] = '\0';

        data += copy_len;
        size -= copy_len;
    }

    struct args_value *vals = args_from_vector(args, argv);

    if (size < 52) {
        // Cleanup
        for (int i = 0; i < args; i++) free(argv[i]);
        free(argv);
        for (int i = 0; i < args; i++) free(vals[i].string);
        free(vals);
        return 0;
    }

    char parse_str[51];
    parse_str[50] = '\0';
    memcpy(parse_str, data, 50);
    

    struct args_parse parse = {
		parse_str,
		data[50],
		data[51],
		NULL,
	};
    data += 52;
    size -= 52;
    
    char *error = NULL;
    struct args *args_parsed = args_parse(&parse, vals, args, &error);
    if (error != NULL || !args_parsed || size < 15) {
        free(error);
        for (int i = 0; i < args; i++) free(argv[i]);
        free(argv);
        for (int i = 0; i < args; i++) free(vals[i].string);
        free(vals);
        if (args_parsed != NULL) args_free(args_parsed);
        return 0;
        }
    
    char *buf = args_print(args_parsed);
    int has = args_has(args_parsed, data[0]);
    data++;
    size--;
    char *get = args_get(args_parsed, data[0]);
    data++;
    size--;
    struct args_entry *entry;
    char first = args_first(args_parsed, &entry);
    if (entry != NULL) char next = args_next(&entry);
    int count = args_count(args_parsed);
    struct args_value *value = args_values(args_parsed);
    value = args_value(args_parsed, data[0]);
    value = args_first_value(args_parsed, data[1]);
    if (value != NULL) value = args_next_value(value);
    data += 2;
    size -= 2;
    char *argument_string = args_string(args_parsed, data[0]);
    data++;
    size--;

    struct args *copy = args_copy(args_parsed, args, argv);
    if (copy == NULL) {
        for (int i = 0; i < args; i++) free(argv[i]);
        free(argv);
        for (int i = 0; i < args; i++) free(vals[i].string);
        free(vals);
        args_free(args_parsed);
        free(buf);
        return 0;
    }

    // Cleanup
    for (int i = 0; i < args; i++) free(argv[i]);
    free(argv);
    for (int i = 0; i < args; i++) free(vals[i].string);
    free(vals);
    free(buf);
    
    int argc;
    char **argvs;
    args_to_vector(copy, &argc, &argvs);
    cmd_free_argv(argc, argvs);
    if (copy != NULL) args_free(copy);

    long long percentage = args_percentage(args_parsed, data[0], data[1], data[2], data[3], &error);
    data += 4;
    size -= 4;
    if (error != NULL || size < 3) {
        free(error);
        args_free(args_parsed);
        return 0;
    }

    long long str_to_num = args_strtonum(args_parsed, data[0], data[1], data[2], &error);
    data += 3;
    size -= 3;
    if (error != NULL || size < 4) free(error);
    if (args_parsed != NULL) args_free(args_parsed);

    return 0;
}
