//
// Created by victor on 5/1/25.
//

#include "cli.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
  cli_node_t* node = cli_node_create();
  if (node == NULL) {
    fprintf(stderr, "Failed to create CRABS node.\n");
    return 1;
  }

  cli_result_e result = cli_dispatch(node, argc, argv);

  cli_node_destroy(node);
  return (int)result;
}