#include <linux/types.h>


struct tpool_data {
    __u32 amount_targets;
    __u32 amount_current;
    __u64 read_bytes;
    __u64 write_bytes;
};

struct tpool_params {
    pid_t* task_pid_arr;
    __u32 amount;
};
