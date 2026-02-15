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

BPF_HASH(start, u64, struct start_t);
BPF_HASH(stats, u32, struct stats_t);

int trace_enter(struct pt_regs *ctx, u32 id)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct start_t s = {};
    s.ts = bpf_ktime_get_ns();
    s.id = id;

    start.update(&pid_tgid, &s);
    return 0;
}

int trace_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_t *sp = start.lookup(&pid_tgid);
    if (!sp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - sp->ts;
    u32 id = sp->id;

    start.delete(&pid_tgid);

    struct stats_t zero = {};
    struct stats_t *stat = stats.lookup_or_init(&id, &zero);

    stat->count += 1;
    stat->total_ns += delta;
    if (delta > stat->max_ns)
        stat->max_ns = delta;

    return 0;
}
"""

b = BPF(text=bpf_program)

# 監視するsyscall一覧
SYSCALLS = {
    "read": 0,
    "write": 1,
    "openat": 2,
    "fsync": 3,
}

for name, sid in SYSCALLS.items():
    fn = f"__x64_sys_{name}"
    b.attach_kprobe(event=fn, fn_name="trace_enter", args=[sid])
    b.attach_kretprobe(event=fn, fn_name="trace_exit")

print("Tracing syscalls... Ctrl+C to stop.")

def print_stats():
    print("%-10s %-10s %-12s %-12s" % ("SYSCALL", "COUNT", "AVG(us)", "MAX(us)"))
    for name, sid in SYSCALLS.items():
        stat = b["stats"].get(sid)
        if stat:
            avg = (stat.total_ns / stat.count) / 1000
            max_us = stat.max_ns / 1000
            print("%-10s %-10d %-12.2f %-12.2f" %
                  (name, stat.count, avg, max_us))

def signal_handler(sig, frame):
    print("\n")
    print_stats()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

while True:
    sleep(1)
