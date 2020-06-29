#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
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
    struct traceset_data* data;
    struct list_head tracees;
};


/*
 * allocate traceset with empty fields
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
    struct tpool_target* target_current;
    struct tpool_target* target_next;
    struct page* data_page;
    // TODO: verify no need to free pid struct?
    // free data
    data_page = virt_to_page((unsigned long) traceset->data);
    kunmap(data_page);
    __free_page(data_page);
    // free tracees
    list_for_each_entry_safe(target_current, target_next, &traceset->tracees, list_node) {
        // TODO: need to also delete list entry?
        kfree(target_current);
    }
    kfree(traceset);
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
    struct traceset_data* tp_data = traceset->data;
    struct list_head* tracees = &traceset->tracees;
    struct tpool_target* target_cursor;
    struct task_struct* task_cursor;
    struct pid* pid_struct_cursor;

    printk( KERN_DEBUG "TPOOL-WORKER: check if traceset %d tracer is alive\n", id);
    task_cursor = get_pid_task(traceset->tracer, PIDTYPE_PID);
    if (task_cursor == NULL) {
        printk( KERN_DEBUG "TPOOL-WORKER: traceset %d tracer is not alive\n", id);
        idr_remove(&tpool_module_map, id);
        free_traceset(traceset);
        return;
    }

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
    spin_lock(&traceset_module_lock);
    if (idr_is_empty(&tpool_module_map)) {
        printk( KERN_DEBUG "TPOOL-WORKER: 0 tracesets registered, stopping\n");
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
    /* struct example_data* datap = file->private_data; */
    int* datap = file->private_data;
	unsigned long pfn = virt_to_phys(datap) >> PAGE_SHIFT;
	unsigned long len = vma->vm_end - vma->vm_start;
	return remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot);
}


static struct file_operations shared_data_fops = 
{
    .mmap = shared_data_mmap,
};


static pid_t* copy_alloc_target_pids(pid_t __user * task_pids, int amount)
{

    // copy pid array from user space
    unsigned long l = sizeof(pid_t) * amount;
    pid_t* tracee_pids = kmalloc(l, GFP_KERNEL);
    if (!tracee_pids) {
        printk( KERN_DEBUG "TPOOL: could not allocate new tracee array\n");
        return NULL;
    }
    printk( KERN_DEBUG "TPOOL: need to copy %lu bytes from user\n", l);
    l = copy_from_user(tracee_pids, task_pids, sizeof(pid_t) * amount);
    if (l != 0) {
        printk( KERN_DEBUG "TPOOL: could not copy data from user\n");
        printk( KERN_DEBUG "TPOOL: %lu bytes not copied\n", l);
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
        printk( KERN_DEBUG "TPOOL: getting unused fd failed\n");
        return -1;
    }

	filp = anon_inode_getfile("traceset_data", &shared_data_fops, 
                                tdata, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
        printk( KERN_DEBUG "TPOOL: getting file failed\n");
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
 */
SYSCALL_DEFINE3(traceset_register, int, traceset_id, pid_t __user *, task_pids, int, amount)
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
        traceset = allocate_traceset();
        if (!traceset) {
            printk( KERN_DEBUG "TPOOL: could not allocate new traceset\n");
            spin_unlock(&traceset_module_lock);
            return -ENOMEM;
        }
        traceset_id = idr_alloc(&tpool_module_map, traceset, 0, 100, GFP_KERNEL);
        if (traceset_id < 0) {
            printk( KERN_DEBUG "TPOOL: could not insert new traceset in map\n");
            free_traceset(traceset);
            spin_unlock(&traceset_module_lock);
            return -EFAULT;
        }
        printk( KERN_DEBUG "TPOOL: inserted new traceset with id %d\n", traceset_id);
        traceset->tracer = task_pid(current);
        traceset->data->amount_targets = amount;
        traceset->data->amount_current = 0;
        traceset->data->traceset_id = traceset_id;
    }
    else {
        is_new = false;
        traceset = idr_find(&tpool_module_map, traceset_id);
        if (!traceset) {
            printk( KERN_DEBUG "TPOOL: could not find traceset with id %d\n", traceset_id);
            goto err;
        }
    }

    // copy pid array from user space
    tracee_pids = copy_alloc_target_pids(task_pids, amount);
    if (!tracee_pids) {
        goto err;
    }

    // add targets to traceset
    for (i = 0; i < amount; i++) {
        if (!add_target(tracee_pids[i], traceset)) {
            printk( KERN_DEBUG "TPOOL: adding target to list failed\n");
        }
    }

    fd = get_traceset_data_fd(traceset->data);
    if (fd < 0) {
        kfree(tracee_pids);
        goto err;
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
 */
SYSCALL_DEFINE3(traceset_deregister, int, traceset_id, pid_t __user *, task_pids, int, amount)
{
    printk( KERN_DEBUG "TPOOL: not implemented\n");
    return -EFAULT;
}

