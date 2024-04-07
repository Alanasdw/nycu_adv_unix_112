#include <dlfcn.h>
#include <stdio.h>
#include <regex.h>

FILE *fopen( const char *restrict pathname, const char *restrict mode)
{
    FILE *(* old_fopen)( const char *, const char *) = NULL;
    FILE *retval = NULL;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if ( handle)
    {
        old_fopen = dlsym( handle, "fopen");
        retval = old_fopen( pathname, mode);
        dlclose( handle);
        handle = NULL;
    }// if

    fflush( stdout);
    printf("[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, retval);
    // use regcomp, regexec, regfree to match pattern
    fflush( stdout);

    return retval;
}

