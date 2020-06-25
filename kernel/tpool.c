#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/workqueue.h>

#include <uapi/linux/tpool.h>

static void work_handler(struct work_struct* work_arg);

/* ==== statically allocated global data ==== */
/* traceset id -> traceset hashmap */
DEFINE_IDR(tpool_module_map);
/* wrapper for the worker function */
DECLARE_DELAYED_WORK(update_work, work_handler);

struct tpool_target {
    pid_t task_pid;
    struct list_head list_node;
};

// TODO: add tracer field
struct tpool_traceset {
    struct tpool_data* data;
    struct list_head tracees;
};


/*
 * allocate traceset with empty tracee list
 */
static struct tpool_traceset* allocate_traceset(void) 
{
    struct page* data_page;
    struct tpool_traceset* new_traceset = kmalloc(sizeof(struct tpool_traceset), GFP_KERNEL);
    if (!new_traceset) {
        return NULL;
    }
    data_page = alloc_page(GFP_KERNEL);
    if (!data_page) {
        printk( KERN_DEBUG "TPOOL: alloc data page failed\n");
        return NULL;
    }
    new_traceset->data = kmap(data_page);
    INIT_LIST_HEAD(&new_traceset->tracees);
    return new_traceset;
}

static void free_traceset(struct tpool_traceset* traceset)
{
    return;
}

static bool add_target(pid_t task_pid, struct tpool_traceset* traceset) 
{
    struct tpool_target* new_target = kmalloc(sizeof(struct tpool_target), GFP_KERNEL);
    if (!new_target) {
        printk( KERN_DEBUG "TPOOL: kmalloc new target failed\n");
        return false;
    }
    new_target->task_pid = task_pid;
    INIT_LIST_HEAD(&new_target->list_node);
    list_add(&new_target->list_node, &traceset->tracees);
    traceset->data->amount_current++;
    return true;
}

static void update_traceset_data(int id, struct tpool_traceset* traceset)
{
    struct tpool_data* tp_data = traceset->data;
    struct list_head* tracees = &traceset->tracees;
    struct tpool_target* target_cursor;
    struct task_struct* task_cursor;
    struct pid* pid_struct_cursor;

    printk( KERN_DEBUG "TPOOL-WORKER: update traceset %d\n", id);
    tp_data->read_bytes = 0;
    tp_data->write_bytes = 0;
    
    list_for_each_entry(target_cursor, tracees, list_node) {
        // TODO: NEEDS SYNCHRONIZATION FOR READING TASK STRUCT AFTER OBTAINING IT
        pid_struct_cursor = find_get_pid(target_cursor->task_pid);
        // in case pid struct is null pid_task will return null
        task_cursor = pid_task(pid_struct_cursor, PIDTYPE_PID);
        if (task_cursor == NULL) {
            printk( KERN_DEBUG "TPOOL-WORKER: target task %d not found\n", target_cursor->task_pid);
        }
        else {
            printk( KERN_DEBUG "TPOOL-WORKER: target task %d found\n", target_cursor->task_pid);
            tp_data->read_bytes += task_cursor->ioac.read_bytes;
            tp_data->write_bytes += task_cursor->ioac.write_bytes;
        }
    }
}

static int __update_traceset_data(int id, void* traceset, void* unused)
{
    update_traceset_data(id, traceset);
    return 0;
}

static void work_handler(struct work_struct* work_arg) 
{
    printk( KERN_DEBUG "TPOOL-WORKER: start execution\n");
    idr_for_each(&tpool_module_map, __update_traceset_data, NULL);
    schedule_delayed_work(&update_work, 10 * HZ);
}

/* SYSCALLS */
SYSCALL_DEFINE2(tpool_register, pid_t __user *, task_pids, __u32, amount)
{
    __u32 i;
    unsigned long l;
    int traceset_id;
    struct tpool_traceset* new_traceset;
    bool first_call = idr_is_empty(&tpool_module_map);

    /* init traceset and id, insert in traceset map */
    new_traceset = allocate_traceset();
    if (!new_traceset) {
        printk( KERN_DEBUG "TPOOL: could not allocate new traceset\n");
        return -ENOMEM;
    }
    traceset_id = idr_alloc(&tpool_module_map, new_traceset, 0, 100, GFP_KERNEL);
    if (traceset_id < 0) {
        printk( KERN_DEBUG "TPOOL: could not insert new traceset in map\n");
        free_traceset(new_traceset);
        return traceset_id;
    }
    printk( KERN_DEBUG "TPOOL: inserted new traceset with id %d\n", traceset_id);
    new_traceset->data->amount_targets = amount;
    new_traceset->data->amount_current = 0;

    // copy pid array from user space
    l = sizeof(pid_t) * amount;
    pid_t* pids = kmalloc(l, GFP_KERNEL);
    printk( KERN_DEBUG "TPOOL: need to copy %lu bytes from user\n", l);
    l = copy_from_user(pids, task_pids, sizeof(pid_t) * amount);
    if (l != 0) {
        // TODO: free traceset resources
        printk( KERN_DEBUG "TPOOL: could not copy data from user\n");
        printk( KERN_DEBUG "TPOOL: %lu bytes not copied\n", l);
        return -EFAULT;
    }

    // add targets to traceset
    for (i = 0; i < amount; i++) {
        if (!add_target(pids[i], new_traceset)) {
            printk( KERN_DEBUG "TPOOL: adding target to list failed\n");
        }
    }

    // if no tracesets registered yet, startup the background updater
    if (first_call) {
        work_handler(NULL);
    }
    return traceset_id;
}

SYSCALL_DEFINE2(tpool_stats, struct tpool_data __user *, data, int, traceset_id)
{
    struct tpool_traceset* traceset = idr_find(&tpool_module_map, traceset_id);
    if (!traceset) {
        printk( KERN_DEBUG "TPOOL: could not find traceset with id %d\n", traceset_id);
        return -EFAULT;
    }
    if (copy_to_user(data, traceset->data, sizeof(struct tpool_data))) {
        printk( KERN_DEBUG "TPOOL: could not copy data to user\n");
        return -EFAULT;
    }
    return 0;
}
