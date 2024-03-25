#include <stdio.h>
#include "libmaze.h"

// static void *stored_ptr;

int maze_init()
{
	fprintf(stderr, "MAZE: library init - stored pointer = %p.\n", maze_get_ptr());
    printf("UP112_GOT_MAZE_CHALLENGE\n");
    printf("SOLVER: _main = %p\n", maze_get_ptr());
    return 0;
}
