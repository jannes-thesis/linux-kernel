#ifndef _LINUX_SYSCACCT_H
#define _LINUX_SYSCACCT_H

struct syscacct_info {
    spinlock_t lock;
    struct hlist_head* info;
};

struct syscacct_entry {
    struct hlist_node node;
    int syscall_nr;
    u32 syscall_count;
    u64 syscall_delay;
};

// use locking when registering/deregistering target and when manipulating acct entries
extern void syscacct_tsk_lock(struct task_struct* tsk);
extern void syscacct_tsk_unlock(struct task_struct* tsk);

// called for init task setup (main.c)
extern void syscacct_init_first(void);

// called at task fork, to NULL the accounting info
extern void syscacct_tsk_init(struct task_struct* tsk);

// called when task is registered as target
extern bool syscacct_tsk_register(struct task_struct* tsk, int* syscalls, u32 amount);

extern struct syscacct_entry* syscacct_tsk_find_entry(struct task_struct* tsk, int syscall_nr);

// called when task is deregistered as target
extern void syscacct_tsk_deregister(struct task_struct* tsk);

// called in bad fork cleanup (fork.c) and general free task function (also fork.c)
extern void syscacct_tsk_free(struct task_struct* tsk);

#endif
