#include <stdio.h>
#include <stdlib.h>
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

int f_load( char *line);
int f_si( char *line);
int f_cont( char *line);
int f_info( char *line);
int f_break( char *line);
int f_delete( char *line);
int f_patch( char *line);
int f_syscall( char *line);
int shell();

// info break & reg are in the same function
static char *command_names[] = { "load", "si", "cont", "info", "break", "delete", "patch", "syscall"};
static int (*commands[])( char *) = { f_load, f_si, f_cont, f_info, f_break, f_delete, f_patch, f_syscall};

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
    
    *strchr( line, '\n') = '\0';
    line_len = strlen( line);
    // printf("given line: %s\n", line);

    int retval = 0;

    int flag = 1;
    for ( int i = 0; i < COMTYPE_COUNT; i += 1)
    {
        if ( strstr( line, command_names[ i]) == line)
        {
            flag = 0;
            retval = commands[ i]( line);
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

int f_load( char *line)
{
    printf("*** f_load not finished ***\n");
    return 0;
}

int f_si( char *line)
{
    printf("*** f_si not finished ***\n");
    return 0;
}

int f_cont( char *line)
{
    printf("*** f_cont not finished ***\n");
    return 0;
}

int f_info( char *line)
{
    printf("*** f_info not finished ***\n");
    return 0;
}

int f_break( char *line)
{
    printf("*** f_break not finished ***\n");
    return 0;
}

int f_delete( char *line)
{
    printf("*** f_delete not finished ***\n");
    return 0;
}

int f_patch( char *line)
{
    printf("*** f_patch not finished ***\n");
    return 0;
}

int f_syscall( char *line)
{
    printf("*** f_syscall not finished ***\n");
    return 0;
}
