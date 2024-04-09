#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
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

int is_match( int blacklist_type, const char *restrict target)
{
    // use regcomp, regexec, regfree to match pattern
    int match = REG_NOMATCH;
    regex_t preg;
    regmatch_t match_info[1];
    for ( int i = 0; i < blacklist[ blacklist_type].len; i += 1)
    {
        // printf("before regcomp\n");
        if ( regcomp( &preg, blacklist[ blacklist_type].list[ i], REG_NEWLINE))
        {
            printf("regex compile error on %s\n", blacklist[ blacklist_type].list[ i]);
            exit( 1);
        }// if
        // printf("before regexec\n");
        match = regexec( &preg, target, ARRAY_SIZE( match_info), match_info, 0);
        regfree( &preg);
        if ( match == 0)
        {
            // matched in blacklist
            errno = EACCES;
            break;
        }// if
    }// for i
    return match != REG_NOMATCH;
}

int abs_path( const char *restrict pathname, char **resolved_name)
{
    // [ -1, 0, 1] = [ error, is symlink, not symlink]
    int retval = 0;

    struct stat sb;
    if ( lstat( pathname, &sb) == -1)
    {
        perror("lstat failed");
        retval = -1;
        goto exit;
    }// if

    char *temp = malloc( sizeof(char) * ( sb.st_size + 1));
    if ( temp == NULL)
    {
        perror("malloc failed");
        retval = -1;
        goto exit;
    }// if
    if ( readlink( pathname, temp, sb.st_size + 1) == -1)
    {
        if ( errno != EINVAL)
        {
            perror("readlink failed");
            retval = -1;
        }// if
        else
        {
            // is a normal path
            retval = 1;
            free( temp);
            temp = NULL;
        }// else
        goto exit;
    }// if
    temp[ sb.st_size] = '\0';

    *resolved_name = temp;

exit:
    return retval;
}

FILE *fopen( const char *restrict pathname, const char *restrict mode)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
        atexit( free_blacklist);
    }// if

    FILE *retval = NULL;
    // create absolute pathname with readlink
    char *resolved_name = NULL;
    switch ( abs_path( pathname, &resolved_name))
    {
    case -1:
        goto exit;
        break;
    case 0:
        // is symlink
        // printf("%s symlink to %s\n", pathname, resolved_name);
        break;
    case 1:
        // not symlink path
        // printf("not symlink\n");
        resolved_name = (char *)pathname;
        break;
    
    default:
        break;
    }// switch abs_path

    // printf("before ismatch %s\n", resolved_name);
    // not in blacklist
    if ( !is_match( OPEN, resolved_name))
    {
        // printf("not in blacklist\n");
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

exit:
    if ( resolved_name && resolved_name != pathname)
    {
        free( resolved_name);
    }// if
    resolved_name = NULL;

    fflush( stderr);
    if ( !retval)
    {
        fprintf( stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", pathname, mode);
    }// if
    else
    {
        fprintf( stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, retval);
    }// else
    fflush( stderr);

    return retval;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *restrict stream)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
        atexit( free_blacklist);
    }// if
    printf("my fread called\n");
    return 0;
}
size_t fwrite(const void *ptr,size_t size, size_t nmemb, FILE *restrict stream)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
        atexit( free_blacklist);
    }// if
    printf("my fwrite callled\n");
    return 0;
}
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
        atexit( free_blacklist);
    }// if
    printf("my connect called\n");
    return 0;
}
int getaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
        atexit( free_blacklist);
    }// if
    printf("my getaddrinfo called\n");
    return 0;
}
int system( const char *command)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
        atexit( free_blacklist);
    }// if
    printf("my system called\n");;
    return 0;
}
