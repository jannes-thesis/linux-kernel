#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/workqueue.h>

#include <uapi/linux/tpool.h>

struct tpool_data* global_data;

struct work_container {
    struct work_struct work;
    struct tpool_data* tp_data;
};

struct work_container* w_cont;

static void work_handler(struct work_struct* work_arg) 
{
    // get argument from container
    struct work_container* work_cont = container_of(work_arg, struct work_container, work);
    struct tpool_data* tp_data = work_cont->tp_data;
    
    struct task_struct* task;
    struct task_struct* target_task = NULL;
    int n_tasks = 0;

    printk( KERN_DEBUG "TPOOL-WORKER: start execution\n");

    for_each_process(task) {
        if (task->pid == tp_data->task_pid) {
            target_task = task;
        }
        n_tasks++;
    }
    printk( KERN_DEBUG "TPOOL-WORKER: total amount of tasks: %d\n", n_tasks);

    if (!target_task) {
        printk( KERN_DEBUG "TPOOL-WORKER: target task not found\n");
        return;
    }
    tp_data->read_bytes = target_task->ioac.read_bytes;
    tp_data->write_bytes = target_task->ioac.write_bytes;

    /* printk( KERN_DEBUG "TPOOL-WORKER: reschedule self\n"); */
    /* schedule_delayed_work(work_arg, 10 * HZ); */
}

SYSCALL_DEFINE1(tpool_register, pid_t, task_pid)
{
    // allocate global tpool data
    global_data = kzalloc(sizeof(struct tpool_data), GFP_KERNEL);
    if (!global_data) {
        printk( KERN_DEBUG "TPOOL: kmalloc global data failed\n");
        return -ENOMEM;
    }
    global_data->task_pid = task_pid;

    // allocate container structure holding work item and argument
    w_cont = kmalloc(sizeof(struct work_container), GFP_KERNEL);
    if (!w_cont) {
        printk( KERN_DEBUG "TPOOL: kmalloc work container failed\n");
        kfree(global_data);
        return -ENOMEM;
    }

    // init work item and set argument to point to global tpool data
    INIT_WORK(&w_cont->work, work_handler);
    w_cont->tp_data = global_data;
    schedule_work(&w_cont->work);

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
