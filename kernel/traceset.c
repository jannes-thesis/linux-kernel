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

#define UPDATE_INTERVAL HZ / 10 

static void work_handler(struct work_struct* work_arg);

/* ==== statically allocated global data ==== */
/* traceset id -> traceset hashmap */
DEFINE_IDR(traceset_map);
/* whether update work is scheduled or not */
bool worker_active = false;
/* spinlock for traceset map and active worker var */
DEFINE_SPINLOCK(traceset_module_lock);
/* wrapper for the worker function */
DECLARE_DELAYED_WORK(update_work, work_handler);

struct traceset_target {
    pid_t task_pid;
    struct list_head list_node;
};

struct traceset_info {
    struct pid* tracer;
    struct list_head tracees;
    struct traceset_data* data;
    int amount_syscalls;
    int* syscall_nrs;
    /* always point this to same page and right behind traceset_data */
    struct traceset_syscall_data* syscall_data;
};


/*
 * allocate traceset with empty fields, amount syscall field set
 * allow max of 8 system calls to be traced (arbitrary value, but guarantees all fits in page)
 */
static struct traceset_info* allocate_traceset(int amount_syscalls) 
{
    struct page* data_page;
    int i;
    if (amount_syscalls > 8) {
        return NULL;
    }
    struct traceset_info* new_traceset = kmalloc(sizeof(struct traceset_info), GFP_KERNEL);
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

/* free syscacct info for given target pid */
static void free_target_syscacct(pid_t target_pid) 
{
    struct task_struct* target_task;
    struct pid* pid_struct = find_get_pid(target_pid);
    rcu_read_lock();
    target_task = pid_task(pid_struct, PIDTYPE_PID);
    if (target_task != NULL) {
        syscacct_tsk_lock(target_task);
        syscacct_tsk_deregister(target_task);
        syscacct_tsk_unlock(target_task);
    }
    rcu_read_unlock();
}

/* traceset needs to be locked */
static void free_traceset(struct traceset_info* traceset)
{
    struct traceset_target* target_current;
    struct traceset_target* target_next;
    struct page* data_page;
    // free data and syscall data by unmapping and freeing data page
    data_page = virt_to_page((unsigned long) traceset->data);
    kunmap(data_page);
    __free_page(data_page);
    // free tracees
    list_for_each_entry_safe(target_current, target_next, &traceset->tracees, list_node) {
        list_del(&target_current->list_node);
        free_target_syscacct(target_current->task_pid);
        kfree(target_current);
    }
    kfree(traceset->syscall_nrs);
    kfree(traceset);
    return;
}

/* fails if task is not found or is already target */
/* traceset needs to be locked */
static bool add_target(pid_t task_pid, struct traceset_info* traceset) 
{
    struct task_struct* target_task;
    struct pid* pid_struct;
    struct traceset_target* new_target = kmalloc(sizeof(struct traceset_target), GFP_KERNEL);
    if (!new_target) {
        printk( KERN_DEBUG "TRACESET: kmalloc new target failed\n");
        return false;
    } 
    printk( KERN_DEBUG "TRACESET: adding target %d\n", task_pid);
    pid_struct = find_get_pid(task_pid);
	rcu_read_lock();
    target_task = pid_task(pid_struct, PIDTYPE_PID);
    if (target_task == NULL || target_task->syscalls_accounting.info != NULL) {
        printk( KERN_DEBUG "TRACESET: target task %d not found or already a target, don't add as target\n", task_pid);
        goto err;
    }
    syscacct_tsk_lock(target_task);
    if (!syscacct_tsk_register(target_task, traceset->syscall_nrs, traceset->amount_syscalls)) {
        syscacct_tsk_unlock(target_task);
        printk( KERN_DEBUG "TRACESET: target task %d syscall accounting could not be initalized\n", task_pid);
        goto err;
    }
    syscacct_tsk_unlock(target_task);
    rcu_read_unlock();
    new_target->task_pid = task_pid;
    INIT_LIST_HEAD(&new_target->list_node);
    list_add(&new_target->list_node, &traceset->tracees);
    traceset->data->amount_targets++;
    return true;
err:
    rcu_read_unlock();
    kfree(new_target);
    return false;
}

/* traceset needs to be locked */
static bool remove_target(pid_t task_pid, struct traceset_info* traceset)
{
    struct traceset_target* target_current;
    struct traceset_target* target_next;
    printk( KERN_DEBUG "TRACESET: remove target: %d\n", task_pid);
    list_for_each_entry_safe(target_current, target_next, &traceset->tracees, list_node) {
        if (target_current->task_pid == task_pid) {
            printk( KERN_DEBUG "TRACESET: found target to be removed: %d\n", task_pid);
            // update traceset
            list_del(&target_current->list_node);
            kfree(target_current);
            traceset->data->amount_targets--;
            // deallocate target's syscacct info
            free_target_syscacct(task_pid);
            return true;
        }
    }
    return false;
}

static void update_traceset_data(int id, struct traceset_info* traceset)
{
    struct syscacct_entry* syscall_data_entry;
    struct list_head* tracees = &traceset->tracees;
    struct traceset_target* target_cursor;
    struct traceset_target* target_next;
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
        idr_remove(&traceset_map, id);
        free_traceset(traceset);
        return;
    }

    agg_counts = kzalloc(sizeof(u32) * traceset->amount_syscalls, GFP_KERNEL);
    if (agg_counts == NULL) 
        return;
    agg_times = kzalloc(sizeof(u64) * traceset->amount_syscalls, GFP_KERNEL);
    if (agg_times == NULL) {
        kfree(agg_counts);
        return;
    }

    printk( KERN_DEBUG "TRACESET-WORKER: update traceset %d\n", id);
    // collect aggregated data for all targets
    list_for_each_entry_safe(target_cursor, target_next, tracees, list_node) {
        pid_struct_cursor = find_get_pid(target_cursor->task_pid);
        // need to read task fields in RCU critical section to avoid task_struct to become invalid
	    rcu_read_lock();
        // in case pid struct is null pid_task will return null
        task_cursor = pid_task(pid_struct_cursor, PIDTYPE_PID);
        if (task_cursor == NULL) {
	        rcu_read_unlock();
            printk( KERN_DEBUG "TRACESET-WORKER: target task %d not found\n", target_cursor->task_pid);
            // remove non-existing task from targets
            list_del(&target_cursor->list_node);
            kfree(target_cursor);
            traceset->data->amount_targets--;
        }
        else {
            agg_read_bytes += task_cursor->ioac.read_bytes;
            agg_write_bytes += task_cursor->ioac.write_bytes;
            syscacct_tsk_lock(task_cursor);
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
            syscacct_tsk_unlock(task_cursor);
	        rcu_read_unlock();
            printk( KERN_DEBUG "TRACESET-WORKER: target task %d found\n", target_cursor->task_pid);
        }
    }

    // update traceset data
    for (i = 0; i < traceset->amount_syscalls; i++) {
        traceset->syscall_data[i].count = agg_counts[i];
        traceset->syscall_data[i].total_time = agg_times[i];
    }
    traceset->data->read_bytes = agg_read_bytes;
    traceset->data->write_bytes = agg_write_bytes;
    kfree(agg_counts);
    kfree(agg_times);
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
    if (idr_is_empty(&traceset_map)) {
        printk( KERN_DEBUG "TRACESET-WORKER: 0 tracesets registered, stopping\n");
        worker_active = false;
    }
    else {
        idr_for_each(&traceset_map, __update_traceset_data, NULL);
        /* every 100ms */
        schedule_delayed_work(&update_work, UPDATE_INTERVAL);
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


/*
 * initalize the syscall nr array of given traceset
 * in case of failure syscall nr array will be NULL
 * accepts invalid syscall numbers -> garbage entries that will never be accessed
 */
static int init_syscalls_array(struct traceset_info* traceset, int __user * syscall_nrs, int amount)
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

/* copy target pids from user space to kernel space */
static int copy_alloc_target_pids(pid_t __user * given_pids, int amount, pid_t** tracee_pids)
{
    // copy pid array from user space
    unsigned long l = sizeof(pid_t) * amount;
    *tracee_pids = kmalloc(l, GFP_KERNEL);
    if (*tracee_pids == NULL) {
        printk( KERN_DEBUG "TRACESET: could not allocate new tracee array\n");
        return -ENOMEM;
    }
    printk( KERN_DEBUG "TRACESET: need to copy %lu bytes from user\n", l);
    l = copy_from_user(*tracee_pids, given_pids, sizeof(pid_t) * amount);
    if (l != 0) {
        printk( KERN_DEBUG "TRACESET: could not copy data from user\n");
        printk( KERN_DEBUG "TRACESET: %lu bytes not copied\n", l);
        kfree(*tracee_pids);
        return -EFAULT;
    }
    return 0;
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

/* ========= SYSCALLS ========= */
/*
 * register set of processes to be traced 
 * either pass existing traceset id, or negative int to create a new traceset
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
    struct traceset_info* traceset;
    int ret = 0;
    bool register_new = false;
    pid_t* tracee_pids = NULL;


    spin_lock(&traceset_module_lock);
    if (traceset_id < 0) {
        register_new = true;
        /* init traceset and id, insert in traceset map */
        traceset = allocate_traceset(amount_syscalls);
        if (!traceset) {
            printk( KERN_DEBUG "TRACESET: could not allocate new traceset\n");
            spin_unlock(&traceset_module_lock);
            return -ENOMEM;
        }
        traceset_id = idr_alloc(&traceset_map, traceset, 0, 100, GFP_KERNEL);
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
        traceset = idr_find(&traceset_map, traceset_id);
        if (!traceset) {
            printk( KERN_DEBUG "TRACESET: could not find traceset with id %d\n", traceset_id);
            ret = -EFAULT;
            goto err;
        }
    }

    if (amount_targets > 0) {
        // copy pid array from user space
        ret = copy_alloc_target_pids(task_pids, amount_targets, &tracee_pids);
        if (ret < 0) {
            goto err;
        }
    }

    /* should validate all targets are children of caller (TGIDs equal to caller PID)
     * [using the pidhash map the target TGIDs can be found fast]
     * NOT IMPLEMENTED because it's easier to test with being able to trace any process */
    for (i = 0; i < amount_targets; i++) {
        if (!add_target(tracee_pids[i], traceset)) {
            printk( KERN_DEBUG "TRACESET: adding target to list failed\n");
        }
    }

    if (register_new) {
        ret = get_traceset_data_fd(traceset->data);
        if (ret < 0) {
            kfree(tracee_pids);
            goto err;
        }
    }

    // if worker was inactive, perform one traceset update and schedule worker
    if (!worker_active) {
        worker_active = true;
        idr_for_each(&traceset_map, __update_traceset_data, NULL);
        schedule_delayed_work(&update_work, UPDATE_INTERVAL);
    }

    spin_unlock(&traceset_module_lock);
    return ret;
err:
    if (register_new) {
        idr_remove(&traceset_map, traceset_id);
        free_traceset(traceset);
    }
    spin_unlock(&traceset_module_lock);
    return ret;
}

/*
 * deregister a set of processes from tracing for given traceset
 * if negative amount is passed, then whole traceset will be deregistered and is invalid after
 *
 * on success:
 * return the amount of deregistered targets
 * guarantees that all passed deregister targets are not traced anymore
 * on error:
 * return error code, no targets have been deregistered
 */
SYSCALL_DEFINE3(traceset_deregister, int, traceset_id, pid_t __user *, task_pids, int, amount)
{
    int i;
    pid_t* tracee_pids;
    struct traceset_info* traceset;
    int ret = 0;
    spin_lock(&traceset_module_lock);
    traceset = idr_find(&traceset_map, traceset_id);
    if (!traceset) {
        printk( KERN_DEBUG "TRACESET: could not find traceset with id %d\n", traceset_id);
        ret = -EFAULT;
        goto end;
    }
    if (amount <= 0) {
        ret = traceset->data->amount_targets;
        idr_remove(&traceset_map, traceset_id);
        free_traceset(traceset);
    }
    else {
        // copy pid array from user space
        ret = copy_alloc_target_pids(task_pids, amount, &tracee_pids);
        if (ret < 0) {
            goto end;
        }
        // remove targets from traceset
        for (i = 0; i < amount; i++) {
            ret = 0;
            if (!remove_target(tracee_pids[i], traceset)) {
                printk( KERN_DEBUG "TRACESET: removing target %d failed\n", tracee_pids[i]);
            }
            else {
                ret++;
            }
        }
    }
end:
    spin_unlock(&traceset_module_lock);
    return ret;
}
