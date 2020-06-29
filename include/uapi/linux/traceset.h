#include <linux/types.h>

struct traceset_data {
    int traceset_id;
    __u32 amount_targets;
    __u32 amount_current;
    __u64 read_bytes;
    __u64 write_bytes;
};

