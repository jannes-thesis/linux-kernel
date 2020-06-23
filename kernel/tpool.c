#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <uapi/linux/tpool.h>

struct tpool_data* global_data;

SYSCALL_DEFINE1(tpool_register, pid_t, task_pid)
{
    int ret;
    global_data = kzalloc(sizeof(struct tpool_data), GFP_KERNEL);
    if (!global_data) {
        printk( KERN_DEBUG "TPOOL: kmalloc global data failed\n");
        return -ENOMEM;
    }
    global_data->task_pid = task_pid;
    return 0;
}

SYSCALL_DEFINE1(tpool_stats, struct tpool_data __user *, data)
{
    struct task_struct* target_task;
    struct task_struct* task;
    int n_tasks = 0;
    if (!global_data) {
        printk( KERN_DEBUG "TPOOL: global data not allocated\n");
        return -EINVAL;
    }

    for_each_process(task) {
        if (task->pid == global_data->task_pid) {
            target_task = task;
        }
        n_tasks++;
    }
    printk( KERN_DEBUG "TPOOL: total amount of tasks: %d\n", n_tasks);

    if (!target_task) {
        printk( KERN_DEBUG "TPOOL: target task not found\n");
        return -EINVAL;
    }
    global_data->read_bytes = target_task->ioac.read_bytes;
    global_data->write_bytes = target_task->ioac.write_bytes;
    if (copy_to_user(data, global_data, sizeof(struct tpool_data))) {
        printk( KERN_DEBUG "TPOOL: could not copy data to user\n");
        return -EFAULT;
    }
    return 0;
}
