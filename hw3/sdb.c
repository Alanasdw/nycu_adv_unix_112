#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <errno.h>
#include <linux/ptrace.h>

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
void disassemble();


int child_pid = 0;
// breakpoint storage
typedef struct _sbreakpoint
{
    int number;
    unsigned long address;
} s_breakpoint;


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
        ptrace( PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);// | PTRACE_O_TRACEEXIT);
        child_pid = pid;
        break;
    }// switch

    // check for the program loaded
    if ( child_pid)
    {
        disassemble();
    }// if

exit:
    return retval;
}

int f_si( char *args[], int arg_count)
{
    printf("*** f_si not finished ***\n");
    ptrace( PTRACE_SINGLESTEP, child_pid, 0, 0);

    // stop this process until the return of the child
    // could be stopping or dying child
    int status;
    waitpid( child_pid, &status, 0);
    if ( WIFEXITED( status))
    {
        printf("child dying: %d\n", WEXITSTATUS( status));
        printf("** the target program terminated.\n");
        child_pid = 0;
    }// if
    else if ( WIFSTOPPED( status))
    {
        printf("stopped by signal: %d\n", WSTOPSIG( status));
    }// else if
    // check for the program loaded
    if ( child_pid)
    {
        disassemble();
    }// if

    return 0;
}

int f_cont( char *args[], int arg_count)
{
    printf("*** f_cont not finished ***\n");

    ptrace( PTRACE_CONT, child_pid, 0, 0);

    // stop this process until the return of the child
    // could be stopping or dying child
    int status;
    waitpid( child_pid, &status, 0);
    if ( WIFEXITED( status))
    {
        printf("child dying: %d\n", WEXITSTATUS( status));
        printf("** the target program terminated.\n");
        child_pid = 0;
    }// if
    else if ( WIFSTOPPED( status))
    {
        printf("stopped by signal: %d\n", WSTOPSIG( status));
    }// else if

    // check for the program loaded
    if ( child_pid)
    {
        disassemble();
    }// if

    return 0;
}

int f_info( char *args[], int arg_count)
{
    printf("*** f_info not finished ***\n");

    if ( arg_count == 1 && strncmp( args[ 0], "regs", strlen("regs")) == 0)
    {
        printf("all the registers:\n");
        struct user_regs_struct regs;
        ptrace( PTRACE_GETREGS, child_pid, 0, &regs);

        printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
        printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
        printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
        printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
        printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
        printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
    }// if
    

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
    ptrace( PTRACE_SYSCALL, child_pid, 0, 0);

    // stop this process until the return of the child
    // could be stopping or dying child
    int status;
    waitpid( child_pid, &status, 0);
    if ( WIFEXITED( status))
    {
        printf("child dying: %d\n", WEXITSTATUS( status));
        printf("** the target program terminated.\n");
        child_pid = 0;
    }// if
    else if ( WIFSTOPPED( status))
    {
        printf("stopped by signal: %d\n", WSTOPSIG( status));
        
        struct ptrace_syscall_info sys_info;
        ptrace( PTRACE_GET_SYSCALL_INFO, child_pid, 0, &sys_info);

        struct user_regs_struct regs;
        ptrace( PTRACE_GETREGS, child_pid, 0, &regs);
        if ( sys_info.op == PTRACE_SYSCALL_INFO_ENTRY)
        {
            // start of the system call
            printf("** enter a syscall([%llu]) at [%llx].\n", sys_info.entry.nr, regs.rip);
        }// if
        else
        {
            // end of the system call
            printf("** leave a syscall([%llu]) = [ret] at [%llx].\n", sys_info.exit.rval, regs.rip);
        }// else
        


    }// else if
    // check for the program loaded
    if ( child_pid)
    {
        disassemble();
    }// if

    return 0;
}

void disassemble()
{
    struct user_regs_struct regs;
    ptrace( PTRACE_GETREGS, child_pid, 0, &regs);

    // code space
    // max instruction line is 15 bytes for x86_64
    uint8_t code[ 15 * 5] = { 0};
    int code_len = 0;
    long temp;
    for ( int i = 0; i < 5; i += 1)
    {
        temp = ptrace( PTRACE_PEEKDATA, child_pid, regs.rip + code_len, 0);
        memmove( code + code_len, &temp, sizeof(temp));
        code_len += sizeof(temp);
    }// for i

    
    csh cshandle = 0;

    if ( cs_open( CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
    {
        printf("cs_open failed\n");
        goto exit;
    }// if
    
    cs_insn *inst;
    inst = cs_malloc( cshandle);

    size_t count;
    count = cs_disasm( cshandle, code, code_len, regs.rip, 0, &inst);

    for ( size_t j = 0; j < ( count >= 5 ? 5: count); j += 1)
    {
        printf("0x%" PRIx64 ":\t%s\t%s\n", inst[j].address, inst[j].mnemonic, inst[j].op_str);
    }// for i
    

    cs_free( inst, 1);
    cs_close( &cshandle);
exit:
    return;
}
