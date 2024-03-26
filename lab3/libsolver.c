#include <stdio.h>
#include <dlfcn.h>
#include "libmaze.h"

#define PATH_MAX (1200)

enum e_direction
{
    UP,
    DOWN,
    LEFT,
    RIGHT,
    DIR_COUNT
};

typedef struct 
{
    int x;
    int y;
} s_pos;

static s_pos offset[ 4] = { (s_pos){ 0, -1}, (s_pos){ 0, 1}, (s_pos){ -1, 0}, (s_pos){ 1, 0}};

int maze_init()
{
    printf("UP112_GOT_MAZE_CHALLENGE\n");
    printf("SOLVER: _main = %p\n", maze_get_ptr());

    void (* old_init)() = NULL;
    void *handle = dlopen("libmaze.so", RTLD_LAZY);
    if ( handle)
    {
        old_init = dlsym( handle, "maze_init");
        old_init();
        dlclose( handle);
        handle = NULL;
    }// if

    return 0;
}

static void find_path( s_pos path[], int *path_len, const maze_t *mz)
{
    int visited[ mz -> h][ mz -> w];
    for ( int i = 0; i < mz -> h; i += 1)
    {
        for ( int j = 0; j < mz -> w; j += 1)
        {
            visited[ i][ j] = -1;
        }// for j
    }// for i

    typedef struct
    {
        s_pos pos;
        int depth;
    } s_step;

    s_step stack[ PATH_MAX + 10];
    int stack_top = -1;

    // try to use DFS to walk the maze
    stack_top += 1;
    stack[ stack_top] = (s_step){(s_pos){ mz -> cx, mz -> cy}, 0};
    s_step current;
    while ( stack_top >= 0)
    {
        current = stack[ stack_top];
        stack_top -= 1;

        path[ current.depth] = current.pos;
        visited[ current.pos.y][ current.pos.x] = 1;

        if ( current.pos.x == mz -> ex && current.pos.y == mz -> ey)
        {
            // ended
            break;
        }// if

        int flag = 0;
        for ( int i = 0; i < DIR_COUNT; i += 1)
        {
            if ( mz -> blk[ current.pos.y + offset[ i].y][ current.pos.x + offset[ i].x] == 0 &&
             visited[ current.pos.y + offset[ i].y][ current.pos.x + offset[ i].x] == -1)
            {
                // possible path, add to stack
                stack_top += 1;
                stack[ stack_top] = (s_step){(s_pos){ current.pos.x + offset[ i].x, current.pos.y + offset[ i].y}, current.depth + 1};
                flag += 1;
            }// if
        }// for i
    }// while
    *path_len = stack[ stack_top].depth + 1;

    return;
}

void move_1(maze_t *mz)
{
    s_pos path[ PATH_MAX + 10];
    int path_len = 0;
    
    // walk is fine, but path is not, it is the whole history of DFS
    find_path( path, &path_len, mz);
    
    for ( int i = 0; i < path_len; i += 1)
    {
        printf("(%d, %d) ", path[ i].x, path[ i].y);
    }// for i
    printf("\n");

    printf("path len: %d\n", path_len);

    void (* dir[ 4])(maze_t *mz) = { move_up, move_down, move_left, move_right};
    // construct path with moves
    for ( int i = 1; i < path_len; i += 1)
    {
        // try to match the directions
        for ( int j = 0; j < DIR_COUNT; j += 1)
        {
            if ( path[ i - 1].x + offset[ j].x == path[ i].x &&
                path[ i - 1].y + offset[ j].y == path[ i].y)
            {
                dir[ j]( mz);
                break;
            }// if
        }// for j
    }// for i
    
    return;
}
