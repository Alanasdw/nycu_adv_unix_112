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
            visited[ i][ j] = 0;
        }// for j
    }// for i

    s_pos stack[ PATH_MAX + 10];
    int stack_top = -1;

    // try to use DFS to walk the maze
    stack_top += 1;
    stack[ stack_top] = (s_pos){ mz -> cx, mz -> cy};
    s_pos current;
    while ( stack_top >= 0)
    {
        current = stack[ stack_top];
        stack_top -= 1;

        path[ *path_len] = current;
        *path_len += 1;
        visited[ current.y][ current.x] = 1;

        if ( current.x == mz -> ex && current.y == mz -> ey)
        {
            // ended
            break;
        }// if

        int flag = 0;
        for ( int i = 0; i < DIR_COUNT; i += 1)
        {
            if ( mz -> blk[ current.y + offset[ i].y][ current.x + offset[ i].x] == 0 &&
             visited[ current.y + offset[ i].y][ current.x + offset[ i].x] == 0)
            {
                // possible path, add to stack
                stack_top += 1;
                stack[ stack_top] = (s_pos){ current.x + offset[ i].x, current.y + offset[ i].y};
                flag += 1;
            }// if
        }// for i
    }// while

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
    int next_step[ PATH_MAX + 10];
    for ( int i = 1; i < path_len; i += 1)
    {
        // try to match the directions
        for ( int j = 0; j < DIR_COUNT; j += 1)
        {
            if ( path[ i - 1].x + offset[ j].x == path[ i].x &&
                path[ i - 1].y + offset[ j].y == path[ i].y)
            {
                next_step[ i - 1] = j;
                printf("%d \n", next_step[ i - 1]);
                dir[ j]( mz);
                printf("c pos: %d %d\n", mz ->cx, mz->cy);
                break;
            }// if
        }// for j
    }// for i
    printf("\n");
    printf("c pos: %d %d\n", mz ->cx, mz->cy);
    // construct path with moves
    // for ( int i = 0; i < path_len; i += 1)
    // {
        
    // }// for i
    
    return;
}
