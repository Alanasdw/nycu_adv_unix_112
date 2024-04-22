#define _GNU_SOURCE

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
#include <arpa/inet.h>

#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))
#define MAX_BUF_SIZE (256)

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

typedef struct _sfile_attr
{
    char *name;
    FILE *fptr;
} s_file_attr;

extern int errno;
static int parsed = 0;
static s_list blacklist[ MAX_TYPE_COUNT] = { 0};
static const char *type_name[] = { "open", "read", "write", "connect", "getaddrinfo"};

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
    atexit( free_blacklist);
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
        // printf("[%s] [%s]\n", blacklist[ blacklist_type].list[ i], target);
        // only one * at the end at most
        if ( strchr( blacklist[ blacklist_type].list[ i], '*') != NULL)
        {
            // has a *
            int prefix_len = strchr( blacklist[ blacklist_type].list[ i], '*') - blacklist[ blacklist_type].list[ i];
            if ( strncmp( target, blacklist[ blacklist_type].list[ i], prefix_len) == 0)
            {
                // matched blacklist
                match = 0;
            }// if
        }// if
        else
        {
            // needs exact match
            // printf("before regcomp\n");
            if ( regcomp( &preg, blacklist[ blacklist_type].list[ i], REG_NEWLINE))
            {
                printf("regex compile error on %s\n", blacklist[ blacklist_type].list[ i]);
                exit( 1);
            }// if
            // printf("before regexec\n");
            match = regexec( &preg, target, ARRAY_SIZE( match_info), match_info, 0);
            regfree( &preg);
        }// else


        /*
        // printf("before regcomp\n");
        if ( regcomp( &preg, blacklist[ blacklist_type].list[ i], REG_NEWLINE))
        {
            printf("regex compile error on %s\n", blacklist[ blacklist_type].list[ i]);
            exit( 1);
        }// if
        // printf("before regexec\n");
        match = regexec( &preg, target, ARRAY_SIZE( match_info), match_info, 0);
        regfree( &preg);
        */
        if ( match == 0)
        {
            // matched in blacklist
            errno = EACCES;
            break;
        }// if
    }// for i
    // printf("is match ret %d\n", match != REG_NOMATCH);
    return match != REG_NOMATCH;
}

int abs_path( const char *restrict pathname, char **resolved_name)
{
    // [ -1, 0, 1] = [ error, is symlink, not symlink]
    int retval = 0;

    struct stat sb;
    if ( lstat( pathname, &sb) == -1)
    {
        // perror("lstat failed");
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
    int read_len = readlink( pathname, temp, sb.st_size + 1);
    if ( read_len == -1)
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
    temp[ read_len] = '\0';

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
        // fprintf( stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", pathname, mode);
        char buf[ MAX_BUF_SIZE] = { 0};
        snprintf( buf, MAX_BUF_SIZE - 1, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", pathname, mode);//, retval);
        write( STDERR_FILENO, buf, strlen( buf));
    }// if
    else
    {
        // fprintf( stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, retval);
        char buf[ MAX_BUF_SIZE] = { 0};
        snprintf( buf, MAX_BUF_SIZE - 1, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, retval);
        write( STDERR_FILENO, buf, strlen( buf));
    }// else
    fflush( stderr);

    return retval;
}

int log2file( const char *filename, const char *data, size_t size, size_t nmemb)
{
    // [ 0, 1] = [ success, error]
    int retval = 0;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if ( !handle)
    {
        printf("dlopen error on log2file\n");
        retval = 1;
        goto exit;
    }// if

    FILE *file = NULL;
    FILE *(* old_fopen)( const char *, const char *) = NULL;
    old_fopen = dlsym( handle, "fopen");
    file = old_fopen( filename, "a+");
    if ( !file)
    {
        printf("fopen failed: %s\n", filename);
    }// if

    FILE *(* old_fwrite)( const void *, size_t, size_t, FILE *) = NULL;
    old_fwrite = dlsym( handle, "fwrite");
    old_fwrite( data, size, nmemb, file);


    FILE *(* old_fclose)( FILE *) = NULL;
    old_fclose = dlsym( handle, "fclose");
    old_fclose( file);
    file = NULL;

    dlclose( handle);
    handle = NULL;

exit:
    return retval;
}

char *resolve_name( FILE *stream)
{
    char *filename = NULL;
    char *pathname = calloc( FILENAME_MAX, sizeof(char));
    snprintf( pathname, FILENAME_MAX, "/proc/self/fd/%d", fileno( stream));
    if ( abs_path( pathname, &filename) == -1)
    {
        printf("resolve name error\n");
    }// if
    free( pathname);
    pathname = NULL;
    return filename;
}

int get_output_name( char **output_name, FILE *stream, enum e_type mode)
{
    int retval = 0;
    *output_name = calloc( FILENAME_MAX, sizeof(char));

    // find filename from FILE *
    char *filename = resolve_name( stream);
    if ( !filename)
    {
        // error in abs_path
        printf("get_output_name: filename NULL\n");
        retval = 1;
        goto exit;
    }// if
    // printf(">>in get output name: [%s]\n", pathname);
    // printf(">in get output name: [%s]\n", filename);

    char compressed_name[ MAX_BUF_SIZE] = { 0};
    char *start = strrchr( filename, '/');

    if ( start)
    {
        strcpy( compressed_name, start + 1);
        start = strchr( compressed_name, '.');
        if ( start)
        {
            *start = '\0';
        }// if
    }// if

    snprintf( *output_name, FILENAME_MAX, "%d-%s-%s.log", getpid(), compressed_name, type_name[ mode]);
    
exit:
    if ( filename)
    {
        free( filename);
    }// if
    filename = NULL;

    return retval;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *restrict stream)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
    }// if

    size_t retval = 0;
    char *temp_ptr = calloc( nmemb + 1, size);
    size_t (* old_fread)( void *, size_t, size_t, FILE *) = NULL;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if ( handle)
    {
        old_fread = dlsym( handle, "fread");
        retval = old_fread( temp_ptr, size, nmemb, stream);
        dlclose( handle);
        handle = NULL;
    }// if

    // find out filename
    char *filename = NULL;
    if ( get_output_name( &filename, stream, READ))
    {
        printf("get_output_name failed\n");
        retval = -1;
        goto exit;
    }// if
    // printf("logger: [%s]\n", filename);
    // check fread contents
    if ( retval)
    {
        // log file write
        if ( log2file( filename, temp_ptr, sizeof(char), retval))
        {
            printf("error in log2file\n");
            goto exit;
        }// if
        
        for ( int i = 0; i < blacklist[ READ].len; i += 1)
        {
            if ( strstr( temp_ptr, blacklist[ READ].list[ i]))
            {
                retval = 0;
                break;
            }// if
        }// for i
        // has content held in ptr
        char buf[ MAX_BUF_SIZE] = { 0};
        snprintf( buf, MAX_BUF_SIZE - 1, "[logger] fread(%p, %ld, %ld, %p) = %ld\n", ptr, size, nmemb, stream, retval);
        write( STDERR_FILENO, buf, strlen( buf));

        if ( retval)
        {
            strcpy( ptr, temp_ptr);
        }// if
    }// if

exit:
    free( temp_ptr);
    temp_ptr = NULL;

    free( filename);
    filename = NULL;

    return retval;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *restrict stream)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
    }// if

    size_t retval = 0;
    // find out filename
    char *filename = NULL;
    char esc_ptr[ 2 * strlen((char *)ptr)];
    char buf[ MAX_BUF_SIZE] = { 0};
    if ( get_output_name( &filename, stream, WRITE))
    {
        printf("get_output_name failed\n");
        retval = -1;
        goto exit;
    }// if
    // log file write
    if ( log2file( filename, ptr, sizeof(char), strlen((char *)ptr)))
    {
        printf("error in log2file\n");
        goto exit;
    }// if

    // construct the escaped sequence
    // char esc_ptr[ strlen((char *)ptr)];
    memset( esc_ptr, 0, 2 * strlen((char *)ptr) * sizeof(char));
    int offset = 0;
    for ( int i = 0; ((char *)ptr)[ i] != '\0'; i += 1)
    {
        // possible ones "abefnrtv\'"?"
        switch ( ((char *)ptr)[ i])
        {
        case '\a':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = 'a';
            offset += 1;
            break;
        case '\b':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = 'b';
            offset += 1;
            break;
        case '\e':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = 'e';
            offset += 1;
            break;
        case '\f':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = 'f';
            offset += 1;
            break;
        case '\n':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = 'n';
            offset += 1;
            break;
        case '\r':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = 'r';
            offset += 1;
            break;
        case '\t':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = 't';
            offset += 1;
            break;
        case '\v':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = 'v';
            offset += 1;
            break;
        case '\\':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = '\\';
            offset += 1;
            break;
        case '\'':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = '\'';
            offset += 1;
            break;
        case '\"':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = '\"';
            offset += 1;
            break;
        case '\?':
            esc_ptr[ offset] = '\\';
            offset += 1;
            esc_ptr[ offset] = '?';
            offset += 1;
            break;
        
        default:
            esc_ptr[ offset] = ((char *)ptr)[ i];
            offset += 1;
            break;
        }// switch
    }// for i
    
    // start the validated write operation
    char *pwd_stream = resolve_name( stream);
    // printf("fwrite resolved name:[%s]\n", pwd_stream);
    if ( !is_match( WRITE, pwd_stream))
    {
        size_t (* old_fwrite)( const void *, size_t, size_t, FILE *) = NULL;
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if ( handle)
        {
            old_fwrite = dlsym( handle, "fwrite");
            retval = old_fwrite( ptr, size, nmemb, stream);
            dlclose( handle);
            handle = NULL;
        }// if
    }// if
    else
    {
        errno = EACCES;
    }// else

    free( pwd_stream);
    pwd_stream = NULL;

    // char buf[ MAX_BUF_SIZE] = { 0};
    snprintf( buf, MAX_BUF_SIZE - 1, "[logger] fwrite(\"%s\", %ld, %ld, %p) = %ld\n", esc_ptr, size, nmemb, stream, retval);
    write( STDERR_FILENO, buf, strlen( buf));

exit:
    free( filename);
    filename = NULL;

    return retval;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
    }// if
    // check the ip first

    int retval = 0;
    char ip[ INET6_ADDRSTRLEN]  = { 0};
    switch ( addr -> sa_family)
    {
    case AF_INET:
        inet_ntop( AF_INET, &(((struct sockaddr_in *)addr) -> sin_addr), ip, INET_ADDRSTRLEN);
        break;
    case AF_INET6:
        inet_ntop( AF_INET6, &(((struct sockaddr_in *)addr) -> sin_addr), ip, INET6_ADDRSTRLEN);
        break;
    
    default:
        printf("unknown address family\n");
        retval = -1;
        break;
    }// switch
    // printf("[%s]\n", ip);

    if ( !is_match( CONNECT, ip))
    {
        size_t (* old_connect)( int, const struct sockaddr *, socklen_t) = NULL;
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if ( handle)
        {
            old_connect = dlsym( handle, "connect");
            retval = old_connect( sockfd, addr, addrlen);
            dlclose( handle);
            handle = NULL;
        }// if
    }// if
    else
    {
        retval = -1;
        errno = ECONNREFUSED;
    }// else
    
    char buf[ MAX_BUF_SIZE] = { 0};
    snprintf( buf, MAX_BUF_SIZE - 1, "[logger] connect(%d,\"%s\", %d) = %d\n", sockfd, ip, addrlen, retval);
    write( STDERR_FILENO, buf, strlen( buf));

    return retval;
}

int getaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
    }// if

    int retval = 0;
    if ( !is_match( GETADDRINFO, node))
    {
        size_t (* old_getaddrinfo)( const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if ( handle)
        {
            old_getaddrinfo = dlsym( handle, "getaddrinfo");
            retval = old_getaddrinfo( node, service, hints, res);
            dlclose( handle);
            handle = NULL;
        }// if
    }// if
    else
    {
        retval = EAI_NONAME;
    }//else
    
    char buf[ MAX_BUF_SIZE] = { 0};
    snprintf( buf, MAX_BUF_SIZE - 1, "[logger] getaddrinfo(\"%s\" , %p, %p,%p) = %d\n", node, service, hints, res, retval);
    write( STDERR_FILENO, buf, strlen( buf));

    return retval;
}

int system( const char *command)
{
    // check the if parsed the file
    if ( !parsed)
    {
        parse_conf();
    }// if

    int retval = 0;
    size_t (* old_system)( const char *) = NULL;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if ( handle)
    {
        old_system = dlsym( handle, "system");
        retval = old_system( command);
        dlclose( handle);
        handle = NULL;
    }// if
    
    char buf[ MAX_BUF_SIZE] = { 0};
    snprintf( buf, MAX_BUF_SIZE - 1, "[logger] system(\"%s\") = %d\n", command, retval);
    write( STDERR_FILENO, buf, strlen( buf));

    return 0;
}
