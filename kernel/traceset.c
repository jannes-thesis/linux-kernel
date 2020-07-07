#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscacct.h>
#include <linux/syscalls.h>
#include <linux/workqueue.h>

#include <uapi/linux/traceset.h>

static void work_handler(struct work_struct* work_arg);

/* ==== statically allocated global data ==== */
/* traceset id -> traceset hashmap */
DEFINE_IDR(tpool_module_map);
/* whether update work is scheduled or not */
bool worker_active = false;
/* spinlock for traceset map and active worker var */
DEFINE_SPINLOCK(traceset_module_lock);
/* wrapper for the worker function */
DECLARE_DELAYED_WORK(update_work, work_handler);

struct tpool_target {
    pid_t task_pid;
    struct list_head list_node;
};

struct tpool_traceset {
    struct pid* tracer;
    struct list_head tracees;
    struct traceset_data* data;
    int amount_syscalls;
    int* syscall_nrs;
    /* always point this to same page and right behind traceset_data */
    // TODO: check what maximum amount of tracked syscalls can fit in page
    struct traceset_syscall_data* syscall_data;
};


// TODO: fail if data shared with user does not fit in single page
/*
 * allocate traceset with empty fields, amount syscall field set
 */
static struct tpool_traceset* allocate_traceset(int amount_syscalls) 
{
    struct page* data_page;
    int i;
    struct tpool_traceset* new_traceset = kmalloc(sizeof(struct tpool_traceset), GFP_KERNEL);
    if (!new_traceset) {
        return NULL;
    }
    new_traceset->syscall_nrs = kmalloc(sizeof(int) * amount_syscalls, GFP_KERNEL);
    if (!new_traceset->syscall_nrs) {
        kfree(new_traceset);
        return NULL;
    }
    new_traceset->amount_syscalls = amount_syscalls;
    data_page = alloc_page(GFP_KERNEL);
    if (!data_page) {
        kfree(new_traceset->syscall_nrs);
        kfree(new_traceset);
        printk( KERN_DEBUG "TRACESET: alloc data page failed\n");
        return NULL;
    }
    new_traceset->data = kmap(data_page);
    INIT_LIST_HEAD(&new_traceset->tracees);
    // point syscall data right after data in same page
    new_traceset->syscall_data = (struct traceset_syscall_data*) (new_traceset->data + 1);
    for (i = 0; i < amount_syscalls; i++) {
        new_traceset->syscall_data[i].count = 0;
        new_traceset->syscall_data[i].total_time = 0;
    }
    return new_traceset;
}

static void free_traceset(struct tpool_traceset* traceset)
{
    struct tpool_target* target_current;
    struct tpool_target* target_next;
    struct page* data_page;
    // TODO: verify no need to free pid struct?
    // free data and syscall data by unmapping and freeing data page
    data_page = virt_to_page((unsigned long) traceset->data);
    kunmap(data_page);
    __free_page(data_page);
    // free tracees
    list_for_each_entry_safe(target_current, target_next, &traceset->tracees, list_node) {
        // TODO: need to also delete list entry?
        kfree(target_current);
    }
    kfree(traceset->syscall_nrs);
    kfree(traceset);
    return;
}

// TODO: init target tasks sysacct map 
//       should fail if target is already tracked in other (or same) traceset
static bool add_target(pid_t task_pid, struct tpool_traceset* traceset) 
{
    struct task_struct* target_task;
    struct pid* pid_struct;
    struct tpool_target* new_target = kmalloc(sizeof(struct tpool_target), GFP_KERNEL);
    if (!new_target) {
        printk( KERN_DEBUG "TRACESET: kmalloc new target failed\n");
        return false;
    } 
    printk( KERN_DEBUG "TRACESET: adding target %d\n", task_pid);
    pid_struct = find_get_pid(task_pid);
	rcu_read_lock();
    target_task = pid_task(pid_struct, PIDTYPE_PID);
    if (target_task == NULL || target_task->syscalls_accounting.info != NULL) {
	    rcu_read_unlock();
        kfree(new_target);
        printk( KERN_DEBUG "TRACESET: target task %d not found or already a target, don't add as target\n", task_pid);
        return false;
    }
    syscacct_tsk_init(target_task, traceset->syscall_nrs, traceset->amount_syscalls);
    if (!target_task->syscalls_accounting.info) {
        rcu_read_unlock();
        kfree(new_target);
        printk( KERN_DEBUG "TRACESET: target task %d syscall accounting could not be initalized\n", task_pid);
        return false;
    }
    rcu_read_unlock();
    new_target->task_pid = task_pid;
    INIT_LIST_HEAD(&new_target->list_node);
    list_add(&new_target->list_node, &traceset->tracees);
    traceset->data->amount_targets++;
    return true;
}

// TODO: deallocate syscacct map of target task_struct
// TODO: break loop after removing target once (double addition should be prevented in add_target)
static bool remove_target(pid_t task_pid, struct tpool_traceset* traceset)
{
    struct tpool_target* target_current;
    struct tpool_target* target_next;
    bool ret = false;
    printk( KERN_DEBUG "TRACESET: remove target: %d\n", task_pid);
    list_for_each_entry_safe(target_current, target_next, &traceset->tracees, list_node) {
        if (target_current->task_pid == task_pid) {
            printk( KERN_DEBUG "TRACESET: found target to be removed: %d\n", task_pid);
            list_del(&target_current->list_node);
            kfree(target_current);
            traceset->data->amount_targets--;
            ret = true;
        }
    }
    return ret;
}

static void update_traceset_data(int id, struct tpool_traceset* traceset)
{
    struct traceset_data* tp_data = traceset->data;
    struct syscacct_entry* syscall_data_entry;
    struct list_head* tracees = &traceset->tracees;
    struct tpool_target* target_cursor;
    struct task_struct* task_cursor;
    struct pid* pid_struct_cursor;
    int i;

    u64 agg_read_bytes = 0;
    u64 agg_write_bytes = 0;
    u32* agg_counts;
    u64* agg_times;

    printk( KERN_DEBUG "TRACESET-WORKER: check if traceset %d tracer is alive\n", id);
    task_cursor = get_pid_task(traceset->tracer, PIDTYPE_PID);
    if (task_cursor == NULL) {
        printk( KERN_DEBUG "TRACESET-WORKER: traceset %d tracer is not alive\n", id);
        idr_remove(&tpool_module_map, id);
        free_traceset(traceset);
        return;
    }

    // TODO: handle kzalloc fail
    agg_counts = kzalloc(sizeof(u32) * traceset->amount_syscalls, GFP_KERNEL);
    agg_times = kzalloc(sizeof(u64) * traceset->amount_syscalls, GFP_KERNEL);

    printk( KERN_DEBUG "TRACESET-WORKER: update traceset %d\n", id);
    tp_data->read_bytes = 0;
    tp_data->write_bytes = 0;
    
    list_for_each_entry(target_cursor, tracees, list_node) {
        pid_struct_cursor = find_get_pid(target_cursor->task_pid);
        // need to read task fields in RCU critical section to avoid task_struct to become invalid
	    rcu_read_lock();
        // in case pid struct is null pid_task will return null
        task_cursor = pid_task(pid_struct_cursor, PIDTYPE_PID);
        if (task_cursor == NULL) {
	        rcu_read_unlock();
            printk( KERN_DEBUG "TRACESET-WORKER: target task %d not found\n", target_cursor->task_pid);
        }
        else {
            agg_read_bytes += task_cursor->ioac.read_bytes;
            agg_write_bytes += task_cursor->ioac.write_bytes;
            for (i = 0; i < traceset->amount_syscalls; i++) {
                syscall_data_entry = syscacct_tsk_find_entry(task_cursor, traceset->syscall_nrs[i]);
                if (syscall_data_entry == NULL) {
                    printk( KERN_DEBUG "TRACESET-WORKER: syscall data entry for target not found, nr: %d\n", traceset->syscall_nrs[i]);
                }
                else {
                    agg_counts[i] += syscall_data_entry->syscall_count;
                    agg_times[i] += syscall_data_entry->syscall_delay;
                }
            }
	        rcu_read_unlock();
            printk( KERN_DEBUG "TRACESET-WORKER: target task %d found\n", target_cursor->task_pid);
        }
    }

    for (i = 0; i < traceset->amount_syscalls; i++) {
        traceset->syscall_data[i].count = agg_counts[i];
        traceset->syscall_data[i].total_time = agg_times[i];
    }
    traceset->data->read_bytes = agg_read_bytes;
    traceset->data->write_bytes = agg_write_bytes;
}

static int __update_traceset_data(int id, void* traceset, void* unused)
{
    update_traceset_data(id, traceset);
    return 0;
}

static void work_handler(struct work_struct* work_arg) 
{
    printk( KERN_DEBUG "TRACESET-WORKER: start execution\n");
    spin_lock(&traceset_module_lock);
    if (idr_is_empty(&tpool_module_map)) {
        printk( KERN_DEBUG "TRACESET-WORKER: 0 tracesets registered, stopping\n");
        worker_active = false;
    }
    else {
        idr_for_each(&tpool_module_map, __update_traceset_data, NULL);
        schedule_delayed_work(&update_work, 10 * HZ);
    }
    spin_unlock(&traceset_module_lock);
}

/* SYSCALL HELPERS */

static int shared_data_mmap(struct file *file, struct vm_area_struct *vma)
{
    void* datap = file->private_data;
	unsigned long pfn = virt_to_phys(datap) >> PAGE_SHIFT;
	unsigned long len = vma->vm_end - vma->vm_start;
	return remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot);
}


static struct file_operations shared_data_fops = 
{
    .mmap = shared_data_mmap,
};


// TODO: validation of syscall nr array
/*
 * initalize the syscall nr array of given traceset
 * in case of failure syscall nr array will be NULL
 */
static int init_syscalls_array(struct tpool_traceset* traceset, int __user * syscall_nrs, int amount)
{

    // copy pid array from user space
    unsigned long l = sizeof(int) * amount;
    traceset->syscall_nrs = kmalloc(l, GFP_KERNEL);
    if (!traceset->syscall_nrs) {
        printk( KERN_DEBUG "TRACESET: could not allocate new syscall nrs array\n");
        return -ENOMEM;
    }
    l = copy_from_user(traceset->syscall_nrs, syscall_nrs, sizeof(int) * amount);
    if (l != 0) {
        printk( KERN_DEBUG "TRACESET: could not copy data from user\n");
        printk( KERN_DEBUG "TRACESET: %lu bytes not copied\n", l);
        kfree(syscall_nrs);
        return -EFAULT;
    }
    return 0;
}

// TODO: different errors for mem alloc failure and invalid user data
static pid_t* copy_alloc_target_pids(pid_t __user * task_pids, int amount)
{
    // copy pid array from user space
    unsigned long l = sizeof(pid_t) * amount;
    pid_t* tracee_pids = kmalloc(l, GFP_KERNEL);
    if (!tracee_pids) {
        printk( KERN_DEBUG "TRACESET: could not allocate new tracee array\n");
        return NULL;
    }
    printk( KERN_DEBUG "TRACESET: need to copy %lu bytes from user\n", l);
    l = copy_from_user(tracee_pids, task_pids, sizeof(pid_t) * amount);
    if (l != 0) {
        printk( KERN_DEBUG "TRACESET: could not copy data from user\n");
        printk( KERN_DEBUG "TRACESET: %lu bytes not copied\n", l);
        kfree(tracee_pids);
        return NULL;
    }
    return tracee_pids;
}

static int get_traceset_data_fd(struct traceset_data* tdata)
{
    struct file* filp;
    int fd;
    fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (fd < 0) {
        printk( KERN_DEBUG "TRACESET: getting unused fd failed\n");
        return -1;
    }

	filp = anon_inode_getfile("traceset_data", &shared_data_fops, 
                                tdata, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
        printk( KERN_DEBUG "TRACESET: getting file failed\n");
		put_unused_fd(fd);
        return -1;
	}

	fd_install(fd, filp);
    return fd;
}

/* SYSCALLS */
/*
 * register set of processes to be traced 
 * either pass existing traceset id or -1 to create a new traceset
 *
 * return a file descriptor associated with traceset data,
 * needs to be mmapped in user space 
 *
 * if registering targets for existing set, return 0
 */
SYSCALL_DEFINE5(traceset_register, int, traceset_id, 
                pid_t __user *, task_pids, int, amount_targets,
                int __user *, syscall_nrs, int, amount_syscalls)
{
    int i;
    int fd;
    struct tpool_traceset* traceset;
    pid_t* tracee_pids;
    bool is_new;


    spin_lock(&traceset_module_lock);
    if (traceset_id < 0) {
        is_new = true;
        /* init traceset and id, insert in traceset map */
        traceset = allocate_traceset(amount_syscalls);
        if (!traceset) {
            printk( KERN_DEBUG "TRACESET: could not allocate new traceset\n");
            spin_unlock(&traceset_module_lock);
            return -ENOMEM;
        }
        traceset_id = idr_alloc(&tpool_module_map, traceset, 0, 100, GFP_KERNEL);
        if (traceset_id < 0) {
            printk( KERN_DEBUG "TRACESET: could not insert new traceset in map\n");
            free_traceset(traceset);
            spin_unlock(&traceset_module_lock);
            return -EFAULT;
        }
        printk( KERN_DEBUG "TRACESET: inserted new traceset with id %d\n", traceset_id);
        traceset->tracer = task_pid(current);
        traceset->data->amount_targets = 0;
        traceset->data->traceset_id = traceset_id;
        i = init_syscalls_array(traceset, syscall_nrs, amount_syscalls);
        if (i != 0) {
            free_traceset(traceset);
            spin_unlock(&traceset_module_lock);
            return i;
        }
    }
    else {
        is_new = false;
        traceset = idr_find(&tpool_module_map, traceset_id);
        if (!traceset) {
            printk( KERN_DEBUG "TRACESET: could not find traceset with id %d\n", traceset_id);
            goto err;
        }
    }

    if (amount_targets > 0) {
        // copy pid array from user space
        tracee_pids = copy_alloc_target_pids(task_pids, amount_targets);
        if (!tracee_pids) {
            goto err;
        }
    }

    // add targets to traceset
    // TODO: validate that all targets all children of caller (check if TGIDs are equal)
    //       use the pidhash map to find TGIDs fast
    for (i = 0; i < amount_targets; i++) {
        if (!add_target(tracee_pids[i], traceset)) {
            printk( KERN_DEBUG "TRACESET: adding target to list failed\n");
        }
    }

    if (is_new) {
        fd = get_traceset_data_fd(traceset->data);
        if (fd < 0) {
            kfree(tracee_pids);
            goto err;
        }
    }
    else {
        fd = 0;
    }

    // if worker was inactive, perform one traceset update and schedule worker
    if (!worker_active) {
        worker_active = true;
        idr_for_each(&tpool_module_map, __update_traceset_data, NULL);
        schedule_delayed_work(&update_work, 10 * HZ);
    }

    spin_unlock(&traceset_module_lock);
    return fd;
err:
    if (is_new) {
        idr_remove(&tpool_module_map, traceset_id);
        free_traceset(traceset);
    }
    spin_unlock(&traceset_module_lock);
    return -EFAULT;

}

/*
 * deregister a set of processes from tracing for given traceset
 * if negative amount is passed, then whole traceset will be deregistered and is invalid after
 *
 * return the amount of deregistered targets
 * guarantees that all passed deregister targets are not traced anymore
 */
SYSCALL_DEFINE3(traceset_deregister, int, traceset_id, pid_t __user *, task_pids, int, amount)
{
    struct tpool_traceset* traceset;
    int i;
    int deregister_amount = 0;
    pid_t* tracee_pids;
    spin_lock(&traceset_module_lock);
    traceset = idr_find(&tpool_module_map, traceset_id);
    if (!traceset) {
        printk( KERN_DEBUG "TRACESET: could not find traceset with id %d\n", traceset_id);
        goto err;
    }
    if (amount <= 0) {
        deregister_amount = traceset->data->amount_targets;
        idr_remove(&tpool_module_map, traceset_id);
        free_traceset(traceset);
    }
    else {
        // copy pid array from user space
        tracee_pids = copy_alloc_target_pids(task_pids, amount);
        if (!tracee_pids) {
            goto err;
        }
        // remove targets from traceset
        for (i = 0; i < amount; i++) {
            if (!remove_target(tracee_pids[i], traceset)) {
                printk( KERN_DEBUG "TRACESET: removing target %d failed\n", tracee_pids[i]);
            }
            else {
                deregister_amount++;
            }
        }
    }
    spin_unlock(&traceset_module_lock);
    return deregister_amount;
err:
    spin_unlock(&traceset_module_lock);
    return -EFAULT;
}

