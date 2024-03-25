#include <stdio.h>
#include "libmaze.h"

static void *stored_ptr;

void maze_set_ptr(void *ptr)
{
    stored_ptr = ptr;
    printf("UP112_GOT_MAZE_CHALLENGE\n");
}

// void move_1(maze_t *mz)
// {
//     printf("SOLVER move1: %p\n", stored_ptr);
//     mz->cx = mz->ex;
//     mz->cy = mz->ey - 1;
//     move_down( mz);
// }
