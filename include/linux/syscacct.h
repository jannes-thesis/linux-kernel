#ifndef _LINUX_SYSCACCT_H
#define _LINUX_SYSCACCT_H

struct syscacct_info {
    struct hlist_head* info;
};

struct syscacct_entry {
    struct hlist_node node;
    int syscall_nr;
    u32 syscall_count;
    u64 syscall_delay;
};

// called at task fork, to NULL the accounting info
extern void syscacct_tsk_pre_init(struct task_struct* tsk);

// called when task is registered as target
extern void syscacct_tsk_init(struct task_struct* tsk, int* syscalls, u32 amount);

extern struct syscacct_entry* syscacct_tsk_find_entry(struct task_struct* tsk, int syscall_nr);
extern void syscacct_tsk_free(struct task_struct* tsk);

#endif
