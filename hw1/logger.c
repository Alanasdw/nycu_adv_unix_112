#include <stdio.h>
#include <stdlib.h>
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
    if ( args.output_file && !access( args.output_file, F_OK) && access( args.output_file, R_OK | W_OK))
    {
        // has designated an output file name & file exists & does not have rw access
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

    int child2parent[ 2] = { 0};
    if ( pipe( child2parent))
    {
        perror("pipe child2parent error:");
        status = 1;
        goto exit;
    }// if

    pid_t pid = fork();
    char buf[ 256] = { 0};
    switch ( pid)
    {
    case -1:
        perror("fork:");
        status = 1;
        goto exit;
        break;
    case 0:
        // could install a signal handler to get start signal from parent?
        // close read port
        close( child2parent[ 0]);

        // change the stdout before execvp
        dup2( child2parent[ 1], STDERR_FILENO);
        close( child2parent[ 1]);

        // create sopath
        int sopath_len = strlen( "LD_PRELOAD=") + strlen( args.shared_lib);
        char *sopath = calloc( sopath_len, sizeof(char));
        strcat( sopath, "LD_PRELOAD=");
        strcat( sopath, args.shared_lib);

        char *const envp[] = { sopath, NULL};
        execve( argv[ args.commands], &argv[ args.commands], envp);
        perror("child execve error\n");
        status = 1;
        break;
    
    default:
        // close write port
        close( child2parent[ 1]);

        FILE *stream_out = stderr;
        if ( args.output_file)
        {
            stream_out = fopen( args.output_file, "w+");
        }// if
        while ( read( child2parent[ 0], buf, 256) > 0)
        {
            fprintf( stream_out, "%s", buf);
            memset( buf, 0, sizeof( buf));
        }// while
        if ( args.output_file)
        {
            fflush( stream_out);
            fclose( stream_out);
            stream_out = NULL;
        }// if
        break;
    }// switch

exit:
    // close unused pipes
    for ( int i = 0; i < 2; i += 1)
    {
        if ( child2parent[ i])
        {
            close( child2parent[ i]);
            child2parent[ i] = 0;
        }// if
    }// for i

    return status;
}
