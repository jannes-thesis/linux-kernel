#include <linux/types.h>


struct tpool_data {
    pid_t task_pid;
    __u64 read_bytes;
    __u64 write_bytes;
};
