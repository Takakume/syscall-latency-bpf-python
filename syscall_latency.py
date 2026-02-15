#!/usr/bin/env python3
from bcc import BPF
from time import sleep
import signal
import sys

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct stats_t {
    u64 count;
    u64 total_ns;
    u64 max_ns;
};

struct start_t {
    u64 ts;
    u32 id;
};

struct key_t {
    u32 id;
    u32 pid;
};

BPF_HASH(start, u64, struct start_t);
BPF_HASH(stats, struct key_t, struct stats_t);

static int trace_enter(struct pt_regs *ctx, u32 id)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct start_t s = {};
    s.ts = bpf_ktime_get_ns();
    s.id = id;

    start.update(&pid_tgid, &s);
    return 0;
}

int trace_enter_read(struct pt_regs *ctx) {
    return trace_enter(ctx, 0);
}

int trace_enter_write(struct pt_regs *ctx) {
    return trace_enter(ctx, 1);
}

int trace_enter_openat(struct pt_regs *ctx) {
    return trace_enter(ctx, 2);
}

int trace_enter_fsync(struct pt_regs *ctx) {
    return trace_enter(ctx, 3);
}

int trace_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct start_t *sp = start.lookup(&pid_tgid);
    if (!sp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - sp->ts;
    u32 id = sp->id;

    start.delete(&pid_tgid);

    struct key_t key = {};
    key.id = id;
    key.pid = pid;

    struct stats_t zero = {};
    struct stats_t *stat = stats.lookup_or_init(&key, &zero);

    stat->count += 1;
    stat->total_ns += delta;
    if (delta > stat->max_ns)
        stat->max_ns = delta;

    return 0;
}
"""

b = BPF(text=bpf_program)

SYSCALLS = {
    "read": 0,
    "write": 1,
    "openat": 2,
    "fsync": 3,
}

for name in SYSCALLS.keys():
    fn = f"__x64_sys_{name}"
    b.attach_kprobe(event=fn, fn_name=f"trace_enter_{name}")
    b.attach_kretprobe(event=fn, fn_name="trace_exit")

print("Tracing syscalls... Ctrl+C to stop.")

def print_stats():
    stats = b["stats"]

    for name, sid in SYSCALLS.items():
        print("\n" + name)
        print("-" * 60)
        print("%-10s %-10s %-12s %-12s" % ("PID", "COUNT", "AVG(us)", "MAX(us)"))

        for k, v in stats.items():
            if k.id != sid:
                continue

            avg = (v.total_ns / v.count) / 1000
            max_us = v.max_ns / 1000

            print("%-10d %-10d %-12.2f %-12.2f" %
                  (k.pid, v.count, avg, max_us))

def signal_handler(sig, frame):
    print("\n")
    print_stats()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

while True:
    sleep(1)
