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
#include <signal.h>

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
void disassemble( unsigned long long rip);
void enable_break();
void disable_break();


int child_pid = 0;
// breakpoint storage
typedef struct _sLLnode
{
    struct _sLLnode *next;
    void *data;
} s_LLnode;

typedef struct _sbreakpoint
{
    int number;
    unsigned long long address;
    char orig_inst;
} s_breakpoint;
s_LLnode *break_head = NULL;
int next_num = 0;

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
    if ( break_head)
    {
        // cleanup breaks
        s_LLnode *temp = break_head -> next;
        while ( temp)
        {
            free( break_head -> data);
            break_head -> data = NULL;
            free( break_head);

            break_head = temp;
            temp = break_head -> next;
        }// while

        free( break_head -> data);
        break_head -> data = NULL;
        free( break_head);
        break_head = NULL;
    }// if

    return 1;
}

int f_load( char *args[], int arg_count)
{
    int retval = 0;
    // printf("*** f_load not finished ***\n");
    if ( child_pid)
    {
        kill( child_pid, SIGKILL);
    }// if

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
        // printf("child\n");
        // fflush( NULL);
        ptrace( PTRACE_TRACEME, 0, 0, 0);
        // execv( args[ 0], args);
        execl( args[ 0], args[ 0], NULL);
        perror("exec error: ");
        break;
    
    default:
        // parent process
        // printf("parent\n");
        int status = 0;
        waitpid( pid, &status, 0);
        ptrace( PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);// | PTRACE_O_TRACEEXIT);
        child_pid = pid;
        break;
    }// switch

    // check for the program loaded
    if ( child_pid)
    {
        struct user_regs_struct regs;
        ptrace( PTRACE_GETREGS, child_pid, 0, &regs);
        printf("** program '%s' loaded. entry point %#llx.\n", args[ 0], regs.rip);
        disassemble( regs.rip);
    }// if

exit:
    return retval;
}

int f_si( char *args[], int arg_count)
{
    // printf("*** f_si not finished ***\n");
    if ( child_pid == 0)
    {
        printf("** please load a program first.\n");
        goto exit;
    }// if
    
    ptrace( PTRACE_SINGLESTEP, child_pid, 0, 0);

    // stop this process until the return of the child
    // could be stopping or dying child
    int status;
    waitpid( child_pid, &status, 0);
    if ( WIFEXITED( status))
    {
        // printf("child dying: %d\n", WEXITSTATUS( status));
        printf("** the target program terminated.\n");
        child_pid = 0;
    }// if
    else if ( WIFSTOPPED( status))
    {
        // printf("stopped by signal: %d\n", WSTOPSIG( status));
    }// else if
    // check for the program loaded
    if ( child_pid)
    {
        struct user_regs_struct regs;
        ptrace( PTRACE_GETREGS, child_pid, 0, &regs);
        disassemble( regs.rip);
    }// if
exit:
    return 0;
}

int f_cont( char *args[], int arg_count)
{
    // printf("*** f_cont not finished ***\n");
    if ( child_pid == 0)
    {
        printf("** please load a program first.\n");
        goto exit;
    }// if
    ptrace( PTRACE_CONT, child_pid, 0, 0);

    // stop this process until the return of the child
    // could be stopping or dying child
    int status;
    waitpid( child_pid, &status, 0);
    if ( WIFEXITED( status))
    {
        // printf("child dying: %d\n", WEXITSTATUS( status));
        printf("** the target program terminated.\n");
        child_pid = 0;
    }// if
    else if ( WIFSTOPPED( status))
    {
        // printf("stopped by signal: %d\n", WSTOPSIG( status));
    }// else if

    // check for the program loaded
    if ( child_pid)
    {
        struct user_regs_struct regs;
        ptrace( PTRACE_GETREGS, child_pid, 0, &regs);
        disassemble( regs.rip - 1);
    }// if
exit:
    return 0;
}

int f_info( char *args[], int arg_count)
{
    // printf("*** f_info not finished ***\n");
    if ( child_pid == 0)
    {
        printf("** please load a program first.\n");
        goto exit;
    }// if

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
    else if ( arg_count == 1 && strncmp( args[ 0], "break", strlen("break")) == 0)
    {
        s_LLnode *current = break_head;
        if ( current == NULL)
        {
            // no breakpoints
            printf("** no breakpoints.\n");
        }// if
        else
        {
            int align = 0;
            align = printf("Num%*s", 5, " ");
            printf("Address\n");
            while ( current)
            {
                int cur_offset = align;
                s_breakpoint *cur_data = (s_breakpoint *)current -> data;
                cur_offset -= printf("%d", cur_data -> number);
                printf("%*s%#llx\n", cur_offset, " ", cur_data -> address);

                current = current -> next;
            }// while
        }// else
    }// else if
exit:
    return 0;
}

int f_break( char *args[], int arg_count)
{
    printf("*** f_break not finished ***\n");
    unsigned long long address = strtoull( args[ 0], NULL, 16);
    if ( arg_count != 1)
    {
        goto exit;
    }// if

    unsigned long long data;
    data = ptrace( PTRACE_PEEKTEXT, child_pid, address, 0);
    char *ptr = (char *)&data;
    if ( break_head == NULL)
    {
        // new element
        break_head = calloc( 1, sizeof(s_LLnode));
        s_breakpoint *new_data = calloc( 1, sizeof(s_breakpoint));
        break_head -> data = new_data;
        new_data -> address = address;
        new_data -> number = next_num;
        next_num += 1;
        new_data -> orig_inst = ptr[ 0];
    }// if
    else
    {
        // find end of list
        s_LLnode *end = break_head;
        while ( end -> next)
        {
            end = end -> next;
        }// while
        
        end -> next = calloc( 1, sizeof(s_LLnode));
        end = end -> next;
        s_breakpoint *temp_new = calloc( 1, sizeof(s_breakpoint));
        end -> data = temp_new;
        temp_new -> address = address;
        temp_new -> number = next_num;
        next_num += 1;
        temp_new -> orig_inst = ptr[ 0];
    }// else

    ptr[ 0] = 0xcc;
    ptrace( PTRACE_POKETEXT, child_pid, address, data);
    printf("breakpoint set @ %s => %llu\n", args[ 0], address);

exit:
    return 0;
}

int f_delete( char *args[], int arg_count)
{
    printf("*** f_delete not finished ***\n");

    int flag = 1;
    if ( arg_count != 1)
    {
        goto exit;
    }// if
    
    int target_num = strtol( args[ 0], NULL, 10);
    if ( target_num >= next_num)
    {
        // impossible to exist
        goto exit;
    }// if

    s_LLnode *current = break_head;
    s_LLnode *prev = NULL;
    while ( current)
    {
        s_breakpoint *cur_data = current -> data;

        if ( cur_data -> number == target_num)
        {
            // target matched
            if ( prev == NULL)
            {
                // head is target
                break_head = break_head -> next;
            }// if
            else
            {
                // bypass the about to be deleted one
                prev -> next = current -> next;
            }// else
            free( current -> data);
            current -> data = NULL;
            current -> next = NULL;
            free( current);
            current = NULL;

            printf("** delete breakpoint %d.\n", target_num);
            flag = 0;
            break;
        }// if
        
        prev = current;
        current = current -> next;
    }// while
    

exit:
    if ( flag)
    {
        printf("** breakpoint %s does not exist.\n", args[ 0]);
    }// if

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
        
        // struct ptrace_syscall_info sys_info;
        // ptrace( PTRACE_GET_SYSCALL_INFO, child_pid, 0, &sys_info);

        struct user_regs_struct regs;
        ptrace( PTRACE_GETREGS, child_pid, 0, &regs);
        // printf("syscall rax: %llu\n", regs.rax);
        if ( regs.rax == -ENOSYS)
        {
            // start of the system call
            printf("** enter a syscall(%llu) at %#llx.\n", regs.orig_rax, regs.rip - 2);
        }// if
        else
        {
            // end of the system call
            printf("** leave a syscall(%llu) = %llu at %#llx.\n", regs.orig_rax, regs.rax, regs.rip - 2);
        }// else
    }// else if
    // check for the program loaded
    if ( child_pid)
    {
        struct user_regs_struct regs;
        ptrace( PTRACE_GETREGS, child_pid, 0, &regs);
        // to not miss the syscall instruction
        disassemble( regs.rip - 2);
    }// if

    return 0;
}

void disassemble( unsigned long long rip)
{
    disable_break();
    // code space
    // max instruction line is 15 bytes for x86_64
    uint8_t code[ 15 * 5] = { 0};
    int code_len = 0;
    long temp;
    for ( int i = 0; i < 5; i += 1)
    {
        temp = ptrace( PTRACE_PEEKTEXT, child_pid, rip + code_len, 0);
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
    count = cs_disasm( cshandle, code, code_len, rip, 0, &inst);

    for ( size_t j = 0; j < ( count >= 5 ? 5: count); j += 1)
    {
        int printed = 0;
        printed += printf("%*s%lx:", 6, "", inst[j].address);
        // printf("inst len: %d\n", inst[ j].size);
        for ( int i = 0; i < inst[ j].size; i += 1)
        {
            printed += printf(" %2.2x", inst[ j].bytes[ i]);
        }// for i
        printf("%*s %-10s%s\n", 47 - printed, " ", inst[j].mnemonic, inst[j].op_str);
        
    }// for j

    cs_free( inst, 1);
    cs_close( &cshandle);
exit:

    enable_break();
    return;
}

void disable_break()
{
    s_LLnode *current = break_head;
    while ( current)
    {
        s_breakpoint *cur_data = (s_breakpoint *)current -> data;

        unsigned long long code = 0;
        code = ptrace( PTRACE_PEEKTEXT, child_pid, cur_data -> address, 0);
        // printf("before disable: %llx\n", code);
        char *ptr = (char *)&code;
        ptr[ 0] = cur_data -> orig_inst;
        ptrace( PTRACE_POKETEXT, child_pid, cur_data -> address, code);
        // printf("disabled to:    %llx\n", code);
        cur_data = NULL;
        current = current -> next;
    }// while
    
    return;
}

void enable_break()
{
    s_LLnode *current = break_head;
    while ( current)
    {
        s_breakpoint *cur_data = (s_breakpoint *)current -> data;

        unsigned long long code = 0;
        code = ptrace( PTRACE_PEEKTEXT, child_pid, cur_data -> address, 0);
        // printf("before enable: %llx\n", code);
        char *ptr = (char *)&code;
        ptr[ 0] = 0xcc;
        ptrace( PTRACE_POKETEXT, child_pid, cur_data -> address, code);
        // printf("enabled to:    %llx\n", code);

        cur_data = NULL;
        current = current -> next;
    }// while

    return;
}
