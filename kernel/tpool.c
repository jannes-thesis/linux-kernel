#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/workqueue.h>

#include <uapi/linux/tpool.h>

struct tpool_data* global_data;

/* TARGET LIST */
struct target {
    pid_t task_pid;
    struct list_head list;
};

static LIST_HEAD(target_list);

static bool add_target(pid_t task_pid) 
{
    struct target* new_target = kmalloc(sizeof(struct target), GFP_KERNEL);
    if (!new_target) {
        printk( KERN_DEBUG "TPOOL: kmalloc new target failed\n");
        return false;
    }
    new_target->task_pid = task_pid;
    INIT_LIST_HEAD(&new_target->list);
    list_add(&new_target->list, &target_list);
    return true;
}

static bool is_target(pid_t task_pid)
{
    struct target* current_node;
    list_for_each_entry(current_node, &target_list, list) {
        if (current_node->task_pid == task_pid) {
            return true;
        }
    }
    return false;
}

/* WORKQUEUE ITEM + HANDLER */
struct work_container {
    struct delayed_work work;
    struct tpool_data* tp_data;
};

struct work_container* w_cont;

static void work_handler(struct work_struct* work_arg) 
{
    // get argument from container
    /* struct work_container* work_cont = container_of(work_arg, struct work_container, work); */
    struct delayed_work* del_w = container_of(work_arg, struct delayed_work, work); 
    struct work_container* work_cont = container_of(del_w, struct work_container, work);
    struct tpool_data* tp_data = work_cont->tp_data;
    
    struct task_struct* task;
    int n_tasks = 0;
    int n_found_targets = 0;

    printk( KERN_DEBUG "TPOOL-WORKER: start execution\n");

    tp_data->read_bytes = 0;
    tp_data->write_bytes = 0;
    for_each_process(task) {
        if (is_target(task->pid)) {
            printk( KERN_DEBUG "TPOOL-WORKER: track target %d\n", task->pid);
            tp_data->read_bytes += task->ioac.read_bytes;
            tp_data->write_bytes += task->ioac.write_bytes;
            n_found_targets++;
        }
        n_tasks++;
    }
    printk( KERN_DEBUG "TPOOL-WORKER: total amount of tasks: %d\n", n_tasks);
    printk( KERN_DEBUG "TPOOL-WORKER: total amount of found targets: %d\n", n_found_targets);
    printk( KERN_DEBUG "TPOOL-WORKER: reschedule self\n");
    schedule_delayed_work(del_w, 10 * HZ);
}

/* SYSCALLS */
SYSCALL_DEFINE2(tpool_register, pid_t __user *, task_pids, __u32, amount)
{
    u32 i;
    unsigned long l;
    // copy pid array from user space
    l = sizeof(pid_t) * amount;
    pid_t* pids = kmalloc(l, GFP_KERNEL);
    printk( KERN_DEBUG "TPOOL: need to copy %lu bytes from user\n", l);
    l = copy_from_user(pids, task_pids, sizeof(pid_t) * amount);
    if (l != 0) {
        printk( KERN_DEBUG "TPOOL: could not copy data from user\n");
        printk( KERN_DEBUG "TPOOL: %lu bytes not copied\n", l);
        return -EFAULT;
    }

    // allocate global tpool data
    global_data = kzalloc(sizeof(struct tpool_data), GFP_KERNEL);
    if (!global_data) {
        printk( KERN_DEBUG "TPOOL: kmalloc global data failed\n");
        return -ENOMEM;
    }
    global_data->amount_targets = amount;


    // add targets to target list
    for (i = 0; i < amount; i++) {
        if (!add_target(pids[i])) {
            printk( KERN_DEBUG "TPOOL: adding target to list failed\n");
        }
        else {
            global_data->amount_current++;
        }
    }

    // allocate container structure holding work item and argument
    w_cont = kmalloc(sizeof(struct work_container), GFP_KERNEL);
    if (!w_cont) {
        printk( KERN_DEBUG "TPOOL: kmalloc work container failed\n");
        kfree(global_data);
        return -ENOMEM;
    }

    // init work item and set argument to point to global tpool data
    INIT_DELAYED_WORK(&w_cont->work, work_handler);
    w_cont->tp_data = global_data;
    /* schedule_work(&w_cont->work); */
    schedule_delayed_work(&w_cont->work, 0);

    return 0;
}

SYSCALL_DEFINE1(tpool_stats, struct tpool_data __user *, data)
{
    /* struct task_struct* target_task; */
    /* struct task_struct* task; */
    /* int n_tasks = 0; */
    /* if (!global_data) { */
    /*     printk( KERN_DEBUG "TPOOL: global data not allocated\n"); */
    /*     return -EINVAL; */
    /* } */

    /* for_each_process(task) { */
    /*     if (task->pid == global_data->task_pid) { */
    /*         target_task = task; */
    /*     } */
    /*     n_tasks++; */
    /* } */
    /* printk( KERN_DEBUG "TPOOL: total amount of tasks: %d\n", n_tasks); */

    /* if (!target_task) { */
    /*     printk( KERN_DEBUG "TPOOL: target task not found\n"); */
    /*     return -EINVAL; */
    /* } */
    /* global_data->read_bytes = target_task->ioac.read_bytes; */
    /* global_data->write_bytes = target_task->ioac.write_bytes; */

    if (copy_to_user(data, global_data, sizeof(struct tpool_data))) {
        printk( KERN_DEBUG "TPOOL: could not copy data to user\n");
        return -EFAULT;
    }
    return 0;
}
