#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

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
    EXIT,
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
int f_exit( char *args[], int arg_count);
int shell();


int child_pid = 0;

// info break & reg are in the same function
static char *command_names[] = { "load", "si", "cont", "info", "break", "delete", "patch", "syscall", "exit"};
static int (*commands[])(  char *args[], int arg_count) = { f_load, f_si, f_cont, f_info, f_break, f_delete, f_patch, f_syscall, f_exit};

int main( int argc, char *argv[])
{
    if ( argc > 1)
    {
        // printf("%s\n", argv[ 1]);
        if ( f_load( &argv[ 1], argc - 1))
        {
            goto exit;
        }// if
    }// if

    while ( shell() == 0);
exit:
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
    // prevent the empty line from segfaulting
    if ( line_len == 0)
    {
        goto clean;
    }// if


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

    char **args = calloc( arg_count, sizeof(char *));
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
            // excluding the command name
            retval = commands[ i]( &args[ 1], arg_count - 1);
            break;
        }// if
    }// for i

    if ( flag)
    {
        printf("no commands matched\n");
    }// if

    free( args);
    args = NULL;
    arg_count = 0;

clean:
    free( line);
    line = NULL;
    line_len = 0;

    return retval;
}

int f_exit( char *args[], int arg_count)
{
    return 1;
}

int f_load( char *args[], int arg_count)
{
    int retval = 0;
    printf("*** f_load not finished ***\n");

    // check file access
    // printf("arg count: %d\n", arg_count);
    if ( arg_count < 1)
    {
        printf("load: to few arguments\n");
        retval = 1;
        goto exit;
    }// if
    
    if ( access( args[ 0], X_OK))
    {
        // not permission to execute
        printf("access error\n");
        retval = 1;
        goto exit;
    }// if

    // printf("file accessable\n");

    int pid = fork();
    // int pid = 2;
    // printf("pid =>> %d\n", pid);

    switch ( pid)
    {
    case -1:
        // error happened on fork
        perror("child spawn error: ");
        retval = 1;
        break;

    case 0:
        // child process
        printf("child\n");
        fflush( NULL);
        ptrace( PTRACE_TRACEME, 0, 0, 0);
        // execv( args[ 0], args);
        execl( args[ 0], args[ 0], NULL);
        perror("exec error: ");
        break;
    
    default:
        // parent process
        printf("parent\n");
        int status = 0;
        waitpid( pid, &status, 0);
        ptrace( PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT);
        child_pid = pid;
        break;
    }// switch

exit:
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

    ptrace( PTRACE_CONT, child_pid, 0, 0);

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
