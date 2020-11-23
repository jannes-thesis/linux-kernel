#include <linux/types.h>

struct traceset_data {
    int traceset_id;
    __u32 amount_targets;
    __u64 read_bytes;
    __u64 write_bytes;
	__u64 blkio_delay;
};

/* always in same page right behind traceset_data 
 * same order as given by caller */
struct traceset_syscall_data {
    __u32 count;
    __u64 total_time;
};

