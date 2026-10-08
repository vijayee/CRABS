//
// Created by victor on 5/1/25.
//

#include "cli.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Short label for a dispatch result, printed by the shell when a command
// fails (cli_dispatch's per-command messages carry the detail; this line is
// the REPL's uniform "that didn't work" signal).
static const char* _cli_result_label(cli_result_e result) {
  switch (result) {
    case CLI_OK:            return "ok";
    case CLI_ERR_ARGS:      return "invalid arguments";
    case CLI_ERR_NOT_INIT:  return "node not initialized";
    case CLI_ERR_EXEC:      return "execution failed";
    case CLI_ERR_IO:        return "I/O error";
    case CLI_ERR_NOT_FOUND: return "not found";
  }
  return "unknown error";
}

// Audit A10-7b: interactive shell. Runs a read-eval loop against ONE
// persistent node so multi-command flows (load → seal-key import → mutate →
// save) work in the shipped binary. Per-command errors are reported and the
// loop continues — matching single-shot behavior, where cli_dispatch prints
// the detail and only the exit code carries the failure. The loop ends only
// on 'exit'/'quit' (reported via should_exit) or EOF (Ctrl-D); either way
// the node is destroyed by the caller before returning.
static cli_result_e _run_shell(cli_node_t* node) {
  printf("CRABS shell. Type 'help' for commands, 'exit' to quit.\n");
  char* line = NULL;
  size_t line_capacity = 0;
  bool should_exit = false;
  while (!should_exit) {
    printf("crabs> ");
    fflush(stdout);
    ssize_t line_len = getline(&line, &line_capacity, stdin);
    if (line_len < 0) {
      // EOF or read error: leave the loop; the node is destroyed below.
      printf("\n");
      break;
    }
    cli_result_e result = cli_shell_execute_line(node, line, &should_exit);
    if (result != CLI_OK && !should_exit) {
      fprintf(stderr, "Error: %s\n", _cli_result_label(result));
    }
  }
  free(line);
  return CLI_OK;
}

int main(int argc, char** argv) {
  cli_node_t* node = cli_node_create();
  if (node == NULL) {
    fprintf(stderr, "Failed to create CRABS node.\n");
    return 1;
  }

  // Single-shot semantics are unchanged: argv dispatches exactly as before.
  // Only the new 'shell' keyword enters the REPL; bare invocation (argc < 2)
  // still prints usage and fails via cli_dispatch.
  cli_result_e result;
  if (argc >= 2 && strcmp(argv[1], "shell") == 0) {
    result = _run_shell(node);
  } else {
    result = cli_dispatch(node, argc, argv);
  }

  cli_node_destroy(node);
  return (int)result;
}
