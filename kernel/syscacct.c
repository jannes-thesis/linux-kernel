#include <linux/list.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscacct.h>


#define SYSCALL_MAP_SIZE 8


static int hash_syscall_nr(int syscall_nr) {
    return syscall_nr % SYSCALL_MAP_SIZE;
}

static struct hlist_head* syscacct_init(int* syscalls, u32 amount)
{
    int i;
    struct hlist_head *map;
    struct syscacct_entry *entry;

    map = kmalloc(sizeof(struct hlist_head) * SYSCALL_MAP_SIZE, GFP_KERNEL);
    if (!map) {
        return NULL;
    }
    for (i = 0; i < SYSCALL_MAP_SIZE; i++) {
		INIT_HLIST_HEAD(&map[i]);
    }
    for (i = 0; i < amount; i++) {
        entry = kzalloc(sizeof(struct syscacct_entry), GFP_KERNEL);
        if (entry == NULL) {
            syscacct_free(map);
            return NULL;
        }
        entry->syscall_nr = syscalls[i];
        hlist_add_head(&entry->node, &map[hash_syscall_nr(syscalls[i])]);
    }
    return map;
}


static struct syscacct_entry* syscacct_find_entry(struct hlist_head *map, int syscall_nr)
{
    struct syscacct_entry *entry;
    struct hlist_head *bucket = &map[hash_syscall_nr(syscall_nr)];
    /* printk( KERN_DEBUG "SYSCACCT trying to find entry for syscall nr %d\n", syscall_nr); */
    hlist_for_each_entry(entry, bucket, node) {
        if (entry->syscall_nr == syscall_nr) {
            /* printk( KERN_DEBUG "SYSCACCT found entry for syscall nr %d\n", syscall_nr); */
            return entry;
        }
    }
    /* printk( KERN_DEBUG "SYSCACCT did not find entry for syscall nr %d\n", syscall_nr); */
    return NULL;
}

static void syscacct_free(struct hlist_head *map)
{
    struct syscacct_entry* current;
    struct syscacct_entry* next;
    for (i = 0; i < SYSCALL_MAP_SIZE; i++) {
        hlist_for_each_entry_safe(current, next, &map[i], node) {
            hlist_del(&current->node);
            free(current);
        }
        free(&map[i]);
    }
}

void syscacct_tsk_lock(struct task_struct* tsk) 
{
    spin_lock(&tsk->syscalls_accounting.lock);
}

void syscacct_tsk_unlock(struct task_struct* tsk)
{
    spin_unlock(&tsk->syscalls_accounting.lock);
}

void syscacct_init_first(void) 
{
    syscacct_tsk_init(&init_task);
}

void syscacct_tsk_init(struct task_struct* tsk) 
{
    tsk->syscalls_accounting.info = NULL;
    spin_lock_init(&tsk->syscalls_accounting.lock);
}

/* lock before calling */
bool syscacct_tsk_register(struct task_struct* tsk, int* syscalls, u32 amount) 
{
    printk( KERN_DEBUG "SYSCACCT try init for task %d\n", tsk->pid);
    tsk->syscalls_accounting.info = syscacct_init(syscalls, amount);
}

/* lock before calling */
struct syscacct_entry* syscacct_tsk_find_entry(struct task_struct* tsk, int syscall_nr)
{
    struct hlist_head* acct_info = tsk->syscalls_accounting.info;
    if (acct_info == NULL) {
        return NULL;
    }
    return syscacct_find_entry(acct_info, syscall_nr);
}

/* lock before calling */
void syscacct_tsk_deregister(struct task_struct* tsk)
{
    syscacct_free(tsk->syscalls_accounting.info);
    tsk->syscalls_accounting.info = NULL;
}

/* call on task exit */
void syscacct_tsk_free(struct task_struct* tsk)
{
    spin_lock(&tsk->syscalls_accounting.lock);
    if (tsk->syscalls_accounting.info != NULL) {
        syscacct_tsk_deregister(tsk);
    }
    spin_unlock(&tsk->syscalls_accounting.lock);
}

