#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

enum e_comtype
{
    LOAD,
    SI,
    CONT,
    INFO,
    BREAK,
    DELETE,
    PATCH,
    SYSCALL,
    COMTYPE_COUNT
};

int f_load( char *args[], int arg_count);
int f_si( char *args[], int arg_count);
int f_cont( char *args[], int arg_count);
int f_info( char *args[], int arg_count);
int f_break( char *args[], int arg_count);
int f_delete( char *args[], int arg_count);
int f_patch( char *args[], int arg_count);
int f_syscall( char *args[], int arg_count);
int shell();

// info break & reg are in the same function
static char *command_names[] = { "load", "si", "cont", "info", "break", "delete", "patch", "syscall"};
static int (*commands[])(  char *args[], int arg_count) = { f_load, f_si, f_cont, f_info, f_break, f_delete, f_patch, f_syscall};

int main( int argc, char *argv[])
{
    if ( argc > 1)
    {
        printf("%s\n", argv[ 1]);
    }// if

    while ( shell() == 0);

    return 0;
}


int shell()
{
    // print banner
    printf("(sdb) ");

    char *line = NULL;
    size_t line_len = 0;

    // wait and getline
    while ( getline( &line, &line_len, stdin) == -1);
    // adjust the delimenator that is given by the getline
    *strchr( line, '\n') = '\0';
    line_len = strlen( line);


    // break the string to arguments
    // printf("given line: %s\n", line);
    int arg_count = 1;
    for ( int i = 0; i < line_len; i += 1)
    {
        if ( line[ i] == ' ')
        {
            arg_count += 1;
        }// if
    }// for i

    char *args[ arg_count];
    args[ 0] = strtok( line, " ");
    for ( int i = 1; i < arg_count; i += 1)
    {
        args[ i] = strtok( NULL, " ");
        if ( args[ i] == NULL)
        {
            arg_count = i;
            break;
        }// if
    }// for i
    

    int retval = 0;

    int flag = 1;
    for ( int i = 0; i < COMTYPE_COUNT; i += 1)
    {
        // the command is inside and the first word
        if ( strcmp( args[ 0], command_names[ i]) == 0)
        {
            flag = 0;
            retval = commands[ i]( args, arg_count);
            break;
        }// if
    }// for i

    if ( flag)
    {
        printf("nothing matched\n");
    }// if

    free( line);
    line = NULL;
    line_len = 0;

    return retval;
}

int f_load( char *args[], int arg_count)
{
    int retval = 0;
    printf("*** f_load not finished ***\n");

    // check file access


    // int pid = fork();
    int pid = 2;

    switch ( pid)
    {
    case -1:
        // error happened on fork
        perror("child spawn error: ");
        retval = 1;
        break;

    case 0:
        // child process
        break;
    
    default:
        // parent process
        break;
    }// switch

    return retval;
}

int f_si( char *args[], int arg_count)
{
    printf("*** f_si not finished ***\n");
    return 0;
}

int f_cont( char *args[], int arg_count)
{
    printf("*** f_cont not finished ***\n");
    return 0;
}

int f_info( char *args[], int arg_count)
{
    printf("*** f_info not finished ***\n");
    return 0;
}

int f_break( char *args[], int arg_count)
{
    printf("*** f_break not finished ***\n");
    return 0;
}

int f_delete( char *args[], int arg_count)
{
    printf("*** f_delete not finished ***\n");
    return 0;
}

int f_patch( char *args[], int arg_count)
{
    printf("*** f_patch not finished ***\n");
    return 0;
}

int f_syscall( char *args[], int arg_count)
{
    printf("*** f_syscall not finished ***\n");
    return 0;
}
