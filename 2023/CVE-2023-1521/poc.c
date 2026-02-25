#include <stdio.h>

void createFileInRoot() {
    const char *filename = "/tmp/pwned.txt";
    const char *content = "Testing";

    FILE *file = fopen(filename, "w");

    if (file != NULL) {
        fputs(content, file);
        fclose(file);
        printf("File '%s' created successfully\n", filename);
    } else {
        printf("Failed to create file '%s'\n", filename);
    }
}

__attribute__((constructor))
static void my_constructor() {
    createFileInRoot();
}