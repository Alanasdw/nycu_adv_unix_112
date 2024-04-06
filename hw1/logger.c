#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

extern char *optarg;
extern int optind, opterr, optopt;

typedef struct ss_arguments
{
    char const*output_file;
    char const*shared_lib;
    int commands;
}s_arguments;

static s_arguments args = { 0};
static const char default_shared[] = "./logger.so";

int parse_args( int argc, char *argv[])
{
    int status = 0;

    // find the command first
    char prefix[] = "./";
    // skip the first argument since it will always match
    for ( int i = 1; i < argc; i += 1)
    {
        if ( strncmp( prefix, argv[ i], strlen( prefix)) == 0)
        {
            args.commands = i;
        }// if
    }// for i

    if ( args.commands == 0)
    {
        fprintf( stderr, "error: no command given\n");
        status = 1;
        goto exit;
    }// if
    
    // check the paths of the given file
    char config[] = "config.txt";
    if ( strcmp( argv[ 1], config) != 0)
    {
        fprintf( stderr, "error: %s not matched in 2 argument\n", config);
        status = 1;
        goto exit;
    }// if

    // check optional -o / -p
    if ( args.commands > 2)
    {
        int opt;
        while (( opt = getopt( args.commands, argv, "op")) != -1)
        {
            switch ( opt)
            {
            case 'o':
                args.output_file = argv[ optind];
                break;
            case 'p':
                args.shared_lib = argv[ optind];
                break;
            
            default:
                fprintf( stderr, "Invalid argument: %c\n", opt);
                goto exit;
                break;
            }// switch opt
        }// while
    }// if
    
    if ( args.shared_lib == NULL)
    {
        args.shared_lib = default_shared;
    }// if
    
    // check all permissions
    if ( access( config, R_OK))
    {
        fprintf( stderr, "error: %s permission error\n", config);
        status = 1;
        goto exit;
    }// if
    if ( access( args.shared_lib, R_OK | X_OK))
    {
        fprintf( stderr, "error: %s permission error\n", args.shared_lib);
        status = 1;
        goto exit;
    }// if
    if ( args.output_file && access( args.output_file, R_OK | W_OK))
    {
        fprintf( stderr, "error: %s permission error\n", args.output_file);
        status = 1;
        goto exit;
    }// if
    
    printf("output_file: %s\n", args.output_file);
    printf("sopath: %s\n", args.shared_lib);
    printf("command to run: ");
    for ( int i = args.commands; i < argc; i += 1)
    {
        printf("%s ", argv[ i]);
    }// for i
    printf("\n");
    
exit:
    return status;
}

int main( int argc, char *argv[])
{
    /*
    printf("argc: %d\n", argc);
    for ( int i = 0; i < argc; i += 1)
    {
        printf("%s\n", argv[ i]);
    }// for i
    // */
    
    int status = 0;
    status = parse_args( argc, argv);
    if ( status)
    {
        goto exit;
    }// if

    pid_t pid = fork();
    switch ( pid)
    {
    case -1:
        perror("fork:");
        status = 1;
        goto exit;
        break;
    case 0:
        printf("child\n");
        // could install a signal handler to get start signal from parent
        break;
    
    default:
        printf("child pid is %d\n", pid);
        // maybe use signal to start child and start the printing parent
        // the main checks will be in the library
        while ( wait(NULL) == pid)
        {
            // could do stuff while waiting??
        }// while
        printf("parent process\n");
        break;
    }// switch

exit:
    return status;
}
