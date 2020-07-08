#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscacct.h>


#define SYSCALL_MAP_SIZE 8


// TODO: think about synchronization 
// ---- how to synchronize initialization ?
// ---- could add extra spinlock field in task_struct
// ---- OR single struct field with spinlock field and list_head field
// TODO: think about deallocation
// check static inline void delayacct_tsk_free(struct task_struct *tsk) callsites
// to see how the delaycct struct is deallocated


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
        // TODO: handle alloc error
        entry->syscall_nr = syscalls[i];
        hlist_add_head(&entry->node, &map[hash_syscall_nr(syscalls[i])]);
    }
    return map;
}

static struct hlist_head* syscacct_init_alt(int* syscalls, u32 amount)
{
    int i;
    struct hlist_head *list;
    struct syscacct_entry *entry;

    printk( KERN_DEBUG "SYSCACCT init\n");
    list = kmalloc(sizeof(struct hlist_head), GFP_KERNEL);
    if (!list) {
        printk( KERN_DEBUG "SYSCACCT init fail: malloc failed\n");
        return NULL;
    }
	INIT_HLIST_HEAD(list);
    for (i = 0; i < amount; i++) {
        entry = kzalloc(sizeof(struct syscacct_entry), GFP_KERNEL);
        if (!entry) {
        // TODO: handle alloc error
            printk( KERN_DEBUG "SYSCACCT init fail: zalloc entry failed\n");
        }
        else {
            entry->syscall_nr = syscalls[i];
            hlist_add_head(&entry->node, list);
        }
    }
    printk( KERN_DEBUG "SYSCACCT init return\n");
    return list;
}

static struct syscacct_entry* syscacct_find_entry(struct hlist_head *map, int syscall_nr)
{
    struct syscacct_entry *entry;
    struct hlist_head *bucket = &map[hash_syscall_nr(syscall_nr)];
    printk( KERN_DEBUG "SYSCACCT trying to find entry for syscall nr %d\n", syscall_nr);
    hlist_for_each_entry(entry, bucket, node) {
        if (entry->syscall_nr == syscall_nr) {
            printk( KERN_DEBUG "SYSCACCT found entry for syscall nr %d\n", syscall_nr);
            return entry;
        }
    }
    printk( KERN_DEBUG "SYSCACCT did not find entry for syscall nr %d\n", syscall_nr);
    return NULL;
}

static struct syscacct_entry* syscacct_find_entry_alt(struct hlist_head* list, int syscall_nr)
{
    struct syscacct_entry *entry;
    printk( KERN_DEBUG "SYSCACCT trying to find entry for syscall nr %d\n", syscall_nr);
    hlist_for_each_entry(entry, list, node) {
        if (entry->syscall_nr == syscall_nr) {
            printk( KERN_DEBUG "SYSCACCT found entry for syscall nr %d\n", syscall_nr);
            return entry;
        }
    }
    printk( KERN_DEBUG "SYSCACCT did not find entry for syscall nr %d\n", syscall_nr);
    return NULL;
}

static void syscacct_free(struct hlist_head *map)
{

}

void syscacct_tsk_pre_init(struct task_struct* tsk) {
    tsk->syscalls_accounting.info = NULL;
}

void syscacct_tsk_init(struct task_struct* tsk, int* syscalls, u32 amount) 
{
    // TODO: locking
    printk( KERN_DEBUG "SYSCACCT try init for task %d\n", tsk->pid);
    tsk->syscalls_accounting.info = syscacct_init(syscalls, amount);
}

struct syscacct_entry* syscacct_tsk_find_entry(struct task_struct* tsk, int syscall_nr)
{
    // TODO: locking
    struct hlist_head* acct_info = tsk->syscalls_accounting.info;
    if (acct_info == NULL) {
        return NULL;
    }
    return syscacct_find_entry(acct_info, syscall_nr);
}

void syscacct_tsk_deregister(struct task_struct* tsk)
{
    sysacct_free(tsk->syscalls_accounting.info);
    tsk->syscalls_accounting.info = NULL;
}

/* call on task exit and target deregister */
void syscacct_tsk_free(struct task_struct* tsk)
{
    // TODO: locking
    if (tsk->syscalls_accounting.info != NULL) {
        syscacct_tsk_deregister(tsk);
    }
}

