#include <linux/list.h>
#include <linux/slab.h>

// TODO: think about synchronization 
// ---- how to synchronize initialization ?
// ---- could add extra spinlock field in task_struct
// ---- OR single struct field with spinlock field and list_head field
// TODO: think about deallocation
// check static inline void delayacct_tsk_free(struct task_struct *tsk) callsites
// to see how the delaycct struct is deallocated

#define SYSCALL_MAP_SIZE 8
struct syscacct_entry {
    struct hlist_node node;
    int syscall_nr;
    u32 syscall_count;
    u64 syscall_delay;
};

static int hash_syscall_nr(int syscall_nr) {
    return syscall_nr % SYSCALL_MAP_SIZE;
}

static void syscacct_init(struct hlist_head *map, int* syscalls, u32 amount)
{
    int i;
    struct syscacct_entry *entry;
    map = kmalloc(sizeof(struct hlist_head) * SYSCALL_MAP_SIZE, GFP_KERNEL);
    for (i = 0; i < SYSCALL_MAP_SIZE; i++) {
		INIT_HLIST_HEAD(&map[i]);
    }
    for (i = 0; i < amount; i++) {
        entry = kzalloc(sizeof(struct syscacct_entry), GFP_KERNEL);
        entry->syscall_nr = syscalls[i];
        hlist_add_head(&entry->node, &map[hash_syscall_nr(syscalls[i])]);
    }
}

static struct syscacct_entry* find_sysc_entry(struct hlist_head *map, int syscall_nr)
{
    struct syscacct_entry *entry;
    struct hlist_head *bucket = &map[hash_syscall_nr(syscall_nr)];
    hlist_for_each_entry(entry, bucket, node) {
        if (entry->syscall_nr == syscall_nr) 
            return entry;
    }
    return NULL;
}

static void syscacct_free(struct hlist_head *map)
{

}


