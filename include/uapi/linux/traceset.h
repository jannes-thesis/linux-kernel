#include <linux/types.h>

struct traceset_parameters {
    __u32 amount_targets;
    pid_t* targets;
    __u32 amount_syscalls;
    int* syscall_nrs;
};

struct traceset_data {
    int traceset_id;
    __u32 amount_targets;
    __u32 amount_current;
    __u64 read_bytes;
    __u64 write_bytes;
    // __u32 amount_syscalls; NOT NEEDEED
    /* struct traceset_syscall_data syscalls_data[]; */
    /* 
     * c99 flexible arrary member notation, not supported in kernel (yet) 
     * instead just put the array right behind traceset_data struct in the page
     * size is known by caller (amount of system calls to do accounting for)
     */
};

struct traceset_syscall_data {
    __u32 count;
    __u64 total_time;
};

