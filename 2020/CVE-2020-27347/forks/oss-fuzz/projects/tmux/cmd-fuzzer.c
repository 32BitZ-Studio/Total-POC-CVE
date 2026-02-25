#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sanitizer/lsan_interface.h>
#include "tmux.h"

/* Max fuzzer size of input data */
#define FUZZER_MAXLEN 1024

/* Max number of command-line arguments
   that can be extracted from parsing. */
#define FUZZER_MAXARGS 64

/* Tmux's global event loop */
struct event_base *libevent;

/* Command parsing result */
struct cmd_parse_result *pr;

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const u_char *data, size_t size) {
  if (size > FUZZER_MAXLEN || size < 1)
      return 0;
  
  /* Create a safe, null termianted buffer */
  static char buf[FUZZER_MAXLEN];
  size_t len = size < FUZZER_MAXLEN - 1 ? size : FUZZER_MAXLEN - 1;
  memcpy(buf, data, len);
  buf[len] = '\0';

  // Create argc and argv for command line arguments
  int argc = 0;
  char *argv[FUZZER_MAXARGS + 1];

  // Pointer to the buffer for tokenization
  char *p = buf;

  // Tokenize the Fuzzer generated data into arguments
  while (argc < FUZZER_MAXARGS) {
    // Split the string on delimiter characters
    char *token = strsep(&p, " \t\r\n");
    if (token == NULL)
        break;
    if (*token == '\0') // Skip empty tokens
        continue; 

    argv[argc++] = token;
  }
  argv[argc] = NULL;

  // Skip empty input
  if (argc == 0)
    return 0;

  // Convert arguments to tmux's argument structure
  struct args_value	*values = args_from_vector(argc, argv);

  // Parse the command line arguments
  pr = cmd_parse_from_arguments(values, argc, NULL);
  
  // Free the command parse list if parsing was successful
  if (pr->status == CMD_PARSE_SUCCESS) {    
    cmd_list_free(pr->cmdlist);
  }
  
  // Free parse result and arguments
  free(pr->error);
  args_free_values(values, argc);
  free(values);

  return 0;
}

/* Fuzzer initialization function */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const struct options_table_entry *oe;
    
    /* Create global Tmux environment and options */
    global_environ = environ_create();
    global_options = options_create(NULL);
    global_s_options = options_create(NULL);
    global_w_options = options_create(NULL);
    
    /* Set default values for tmux's options */
    for (oe = options_table; oe->name != NULL; oe++) {
        if (oe->scope & OPTIONS_TABLE_SERVER)
            options_default(global_options, oe);
        if (oe->scope & OPTIONS_TABLE_SESSION)
            options_default(global_s_options, oe);
        if (oe->scope & OPTIONS_TABLE_WINDOW)
            options_default(global_w_options, oe);
    }

    libevent = osdep_event_init();

    
    /* Initialize key input processing and bindings */
    input_key_build();
    key_bindings_init();
        
    return 0;
}