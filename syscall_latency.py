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

BPF_HASH(start, u64, u64);
BPF_HASH(stats, u32, struct stats_t);

int trace_enter(struct pt_regs *ctx, long id)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid_tgid, &ts);
    return 0;
}

int trace_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid_tgid);
    if (!tsp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid_tgid);

    u32 id = PT_REGS_RC(ctx);  // syscall return値ではなく番号が欲しいが簡易版

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

b.attach_kprobe(event="__x64_sys_read", fn_name="trace_enter")
b.attach_kretprobe(event="__x64_sys_read", fn_name="trace_exit")


print("Tracing syscalls... Ctrl+C to stop.")

def print_stats():
    print("%-6s %-10s %-12s %-12s" % ("ID", "COUNT", "AVG(us)", "MAX(us)"))
    for k, v in b["stats"].items():
        avg = (v.total_ns / v.count) / 1000
        max_us = v.max_ns / 1000
        print("%-6d %-10d %-12.2f %-12.2f" %
              (k.value, v.count, avg, max_us))

def signal_handler(sig, frame):
    print("\n")
    print_stats()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

while True:
    sleep(1)

