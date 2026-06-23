#ifndef STRUCTURES_H
#define STRUCTURES_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define FILENAME_LEN 256
#define ARG_LEN 128

#define EVENT_EXECVE   1
#define EVENT_EXECVEAT 2
#define EVENT_CONNECT  3
#define EVENT_ACCEPT   4

struct event_t {
    u64 timestamp_ns;

    u32 event_type;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 auid;

    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];

    char argv0[ARG_LEN];
    char argv1[ARG_LEN];
    char argv2[ARG_LEN];
    char argv3[ARG_LEN];
    char argv4[ARG_LEN];
    char argv5[ARG_LEN];

    u32 saddr;
    u32 daddr;

    u16 sport;
    u16 dport;
    u16 family;
};

BPF_RINGBUF_OUTPUT(events, 256);

#endif 