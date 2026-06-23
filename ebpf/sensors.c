#include <linux/sched.h>
#include <uapi/linux/in.h>
#include <uapi/linux/socket.h>

#include "structures.h"

BPF_PERCPU_ARRAY(event_heap, struct event_t, 1);

struct accept_args_t {
    u64 upeer_sockaddr;
    u64 upeer_addrlen;
};

BPF_HASH(pending_accept, u64, struct accept_args_t);

static inline u16 ntohs16(u16 value)
{
    return __builtin_bswap16(value);
}

static inline u32 get_current_pid(void)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    return (u32)(pid_tgid >> 32);
}

static inline u32 get_current_uid(void)
{
    u64 uid_gid = bpf_get_current_uid_gid();

    return (u32)uid_gid;
}

static inline u32 read_current_ppid(void)
{
    struct task_struct *task = NULL;
    struct task_struct *parent = NULL;
    u32 ppid = 0;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) < 0) {
        return 0;
    }

    if (!parent) {
        return 0;
    }

    if (bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid) < 0) {
        return 0;
    }

    return ppid;
}

static inline struct event_t *get_event_heap(void)
{
    int zero = 0;
    return event_heap.lookup(&zero);
}

static inline void clear_event(struct event_t *event)
{
    if (!event) {
        return;
    }

    event->timestamp_ns = 0;

    event->event_type = 0;
    event->pid = 0;
    event->ppid = 0;
    event->uid = 0;
    event->auid = (u32)-1;

    event->comm[0] = '\0';
    event->filename[0] = '\0';

    event->argv0[0] = '\0';
    event->argv1[0] = '\0';
    event->argv2[0] = '\0';
    event->argv3[0] = '\0';
    event->argv4[0] = '\0';
    event->argv5[0] = '\0';

    event->saddr = 0;
    event->daddr = 0;
    event->sport = 0;
    event->dport = 0;
    event->family = 0;
}

static inline void fill_common(struct event_t *event, u32 event_type)
{
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = event_type;

    event->pid = get_current_pid();
    event->ppid = read_current_ppid();
    event->uid = get_current_uid();

    event->auid = (u32)-1;

    bpf_get_current_comm(event->comm, sizeof(event->comm));
}

#define READ_USER_STR_FIELD(ptr, field)                                      \
    do {                                                                     \
        if (ptr) {                                                           \
            bpf_probe_read_user_str(event->field, sizeof(event->field), ptr);\
        }                                                                    \
    } while (0)

#define READ_ARG(argv_ptr, index, field)                                      \
    do {                                                                      \
        const char *argp = NULL;                                              \
        if (argv_ptr) {                                                       \
            if (bpf_probe_read_user(&argp,                                    \
                                    sizeof(argp),                             \
                                    &((argv_ptr)[index])) == 0) {             \
                if (argp) {                                                   \
                    bpf_probe_read_user_str(event->field,                     \
                                            sizeof(event->field),             \
                                            argp);                            \
                }                                                             \
            }                                                                 \
        }                                                                     \
    } while (0)

static inline int submit_exec_event(const char *filename,
                                    const char *const *argv,
                                    u32 event_type)
{
    struct event_t *event = NULL;

    event = get_event_heap();
    if (!event) {
        return 0;
    }

    clear_event(event);
    fill_common(event, event_type);

    READ_USER_STR_FIELD(filename, filename);

    READ_ARG(argv, 0, argv0);
    READ_ARG(argv, 1, argv1);
    READ_ARG(argv, 2, argv2);
    READ_ARG(argv, 3, argv3);
    READ_ARG(argv, 4, argv4);
    READ_ARG(argv, 5, argv5);

    events.ringbuf_output(event, sizeof(*event), 0);

    return 0;
}

static inline int submit_connect_event(struct sockaddr *uaddr, int addrlen)
{
    struct event_t *event = NULL;
    struct sockaddr_in addr = {};

    if (!uaddr) {
        return 0;
    }

    if (addrlen < sizeof(addr)) {
        return 0;
    }

    if (bpf_probe_read_user(&addr, sizeof(addr), uaddr) < 0) {
        return 0;
    }

    if (addr.sin_family != AF_INET) {
        return 0;
    }

    event = get_event_heap();
    if (!event) {
        return 0;
    }

    clear_event(event);
    fill_common(event, EVENT_CONNECT);

    event->family = addr.sin_family;
    event->daddr = addr.sin_addr.s_addr;
    event->dport = ntohs16(addr.sin_port);

    events.ringbuf_output(event, sizeof(*event), 0);

    return 0;
}

static inline int save_accept_args(u64 upeer_sockaddr, u64 upeer_addrlen)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args_t accept_args = {};

    if (!upeer_sockaddr) {
        return 0;
    }

    if (!upeer_addrlen) {
        return 0;
    }

    accept_args.upeer_sockaddr = upeer_sockaddr;
    accept_args.upeer_addrlen = upeer_addrlen;

    pending_accept.update(&pid_tgid, &accept_args);

    return 0;
}

static inline int submit_accept_event(long ret)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct accept_args_t *saved_args = NULL;
    struct accept_args_t accept_args = {};

    struct event_t *event = NULL;
    struct sockaddr_in addr = {};
    int addrlen = 0;

    saved_args = pending_accept.lookup(&pid_tgid);
    if (!saved_args) {
        return 0;
    }

    accept_args.upeer_sockaddr = saved_args->upeer_sockaddr;
    accept_args.upeer_addrlen = saved_args->upeer_addrlen;

    pending_accept.delete(&pid_tgid);

    if (ret < 0) {
        return 0;
    }

    if (!accept_args.upeer_sockaddr) {
        return 0;
    }

    if (!accept_args.upeer_addrlen) {
        return 0;
    }

    if (bpf_probe_read_user(&addrlen,
                            sizeof(addrlen),
                            (void *)accept_args.upeer_addrlen) < 0) {
        return 0;
    }

    if (addrlen < sizeof(addr)) {
        return 0;
    }

    if (bpf_probe_read_user(&addr,
                            sizeof(addr),
                            (void *)accept_args.upeer_sockaddr) < 0) {
        return 0;
    }

    if (addr.sin_family != AF_INET) {
        return 0;
    }

    event = get_event_heap();
    if (!event) {
        return 0;
    }

    clear_event(event);
    fill_common(event, EVENT_ACCEPT);

    event->family = addr.sin_family;
    event->saddr = addr.sin_addr.s_addr;
    event->sport = ntohs16(addr.sin_port);

    events.ringbuf_output(event, sizeof(*event), 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    return submit_exec_event(args->filename, args->argv, EVENT_EXECVE);
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat)
{
    return submit_exec_event(args->filename, args->argv, EVENT_EXECVEAT);
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    return submit_connect_event(args->uservaddr, args->addrlen);
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept)
{
    return save_accept_args((u64)args->upeer_sockaddr,
                            (u64)args->upeer_addrlen);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept)
{
    return submit_accept_event(args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4)
{
    return save_accept_args((u64)args->upeer_sockaddr,
                            (u64)args->upeer_addrlen);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4)
{
    return submit_accept_event(args->ret);
}