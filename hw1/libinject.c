#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>

#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))

typedef struct _slist
{
    int len;
    char **list;
} s_list;

enum e_type
{
    OPEN,
    READ,
    WRITE,
    CONNECT,
    GETADDRINFO,
    MAX_TYPE_COUNT
};

extern int errno;
static int parsed = 0;
static s_list blacklist[ MAX_TYPE_COUNT] = { 0};
static const char *type_name[] = { "open", "read", "write", "connect", "getaddrinfo"};

static void parse_conf()
{
    parsed = 1;
    char config[] = "config.txt";

    // remember to use the "real dlopen"
    FILE *(* old_fopen)( const char *, const char *) = NULL;
    FILE *retval = NULL;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if ( handle)
    {
        old_fopen = dlsym( handle, "fopen");
        retval = old_fopen( config, "r");
        dlclose( handle);
        handle = NULL;
    }// if

    FILE *conf = retval;

    int state = MAX_TYPE_COUNT;
    char *buf = NULL;
    size_t len = 0;
    while ( getline( &buf, &len, conf) != -1)
    {
        if ( strstr( buf, "BEGIN"))
        {
            // found begin string
            for ( int i = 0; i < MAX_TYPE_COUNT; i += 1)
            {
                if ( strstr( buf, type_name[ i]))
                {
                    state = i;
                    break;
                }// if
            }// for i
        }// if
        else if ( strstr( buf, "END"))
        {
            // found end string
            state = MAX_TYPE_COUNT;
        }// else if
        else
        {
            // continue current state
            if ( state == MAX_TYPE_COUNT)
            {
                printf("ERROR IN %s\n", config);
                exit( 1);
            }// if
            // normal execution
            *( strchr( buf, '\n')) = '\0';
            char *temp = calloc( len + 1, sizeof(char));
            strcpy( temp, buf);
            blacklist[ state].len += 1;
            blacklist[ state].list = realloc( blacklist[ state].list, sizeof(char *) * blacklist[ state].len);
            blacklist[ state].list[ blacklist[ state].len - 1] = temp;
        }// else
        memset( buf, 0, len * sizeof(char));
    }// while
    
    free( buf);
    buf = NULL;
    len = 0;

    fclose( conf);
    conf = NULL;
    return;
}

void free_blacklist()
{
    for ( int i = 0; i < MAX_TYPE_COUNT; i += 1)
    {
        for ( int j = 0; j < blacklist[ i].len; j += 1)
        {
            free( blacklist[ i].list[ j]);
            blacklist[ i].list[ j] = NULL;
        }// for j
        blacklist[ i].len = 0;
    }// for i
    
    return;
}

FILE *fopen( const char *restrict pathname, const char *restrict mode)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
        atexit( free_blacklist);
    }// if

    // use regcomp, regexec, regfree to match pattern
    int match = REG_NOMATCH;
    regex_t preg;
    regmatch_t match_info[1];
    for ( int i = 0; i < blacklist[ OPEN].len; i += 1)
    {
        if ( regcomp( &preg, blacklist[ OPEN].list[ i], REG_NEWLINE))
        {
            printf("regex compile error on %s\n", blacklist[ OPEN].list[ i]);
            exit( 1);
        }// if
        match = regexec( &preg, pathname, ARRAY_SIZE( match_info), match_info, 0);
        regfree( &preg);
        if ( match == 0)
        {
            // matched in blacklist
            errno = EACCES;
            break;
        }// if
    }// for i

    FILE *retval = NULL;
    // not in blacklist
    if ( errno != EACCES)
    {
        FILE *(* old_fopen)( const char *, const char *) = NULL;
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if ( handle)
        {
            old_fopen = dlsym( handle, "fopen");
            retval = old_fopen( pathname, mode);
            dlclose( handle);
            handle = NULL;
        }// if
    }// if

    fflush( stderr);
    fprintf( stderr, "[logger] fopen(\"%s\", \"%s\") = ", pathname, mode);
    if ( !retval)
    {
        fprintf( stderr, "0x0\n");
    }// if
    else
    {
        fprintf( stderr, "%p\n", retval);
    }// else
    fflush( stderr);

    return retval;
}

