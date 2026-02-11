# syscall-latency-bpf

A minimal syscall latency profiler built with eBPF (BCC).

---

## Motivation

When investigating performance issues, `perf` often produces noisy call stacks.

In many cases, what we really want to know is:

> **Which syscall is slow?**

This tool aggregates syscall latency directly in the kernel and reports:

- Call count
- Average latency
- Maximum latency

It focuses purely on syscall latency instead of full stack profiling.

---

## Architecture

This tool uses:

- eBPF (BCC)
- kprobe / kretprobe
- In-kernel hash maps for aggregation

Latency is measured using:

    bpf_ktime_get_ns()

Measurement pattern:

1. kprobe (syscall entry)
   - Store timestamp in `start` map
2. kretprobe (syscall exit)
   - Calculate latency delta
   - Update aggregated statistics in `stats` map

---

## Data Flow

    Userspace (Python)
            ↓
        eBPF Program
            ↓
      kprobe / kretprobe
            ↓
         BPF Maps
            ↓
       Aggregated Output

All aggregation happens inside the kernel to minimize overhead.

---

## BPF Maps

### start

Temporary map storing the start time of in-flight syscalls.

| Key       | Value            |
|-----------|------------------|
| pid_tgid  | start time (ns)  |

`pid_tgid` ensures correct behavior for multi-threaded processes.

---

### stats

Aggregated statistics per syscall.

| Key        | Value                          |
|------------|--------------------------------|
| syscall ID | count, total_ns, max_ns        |

Structure:

```c
struct stats_t {
    u64 count;
    u64 total_ns;
    u64 max_ns;
};
```

---

## Example Output

```
ID     COUNT      AVG(us)      MAX(us)
0      120394     3.42         182.00
1      50432      2.10         50.00
74     120        23000.00     120000.00
```

Where:

- COUNT = number of calls
- AVG(us) = average latency in microseconds
- MAX(us) = maximum observed latency

---

## Environment

Tested on:

- Amazon Linux 2023
- Kernel 6.x
- BCC

---

## Installation

```
sudo dnf install -y bcc python3-bcc kernel-devel clang llvm
```

---

## Usage

```
sudo python3 syscall_latency.py
```

Press `Ctrl+C` to print aggregated statistics.

---

## Why This Is Lightweight

- Uses kprobe/kretprobe (low overhead)
- No per-event user-space communication
- All aggregation happens inside the kernel
- Only summary is printed at exit

Compared to `perf`, this produces significantly less noise and focuses purely on syscall latency.

---

## Limitations

- Currently probes selected syscalls (e.g., read)
- Not container-aware
- Not CO-RE based
- No histogram (only average and max)

---

## Future Improvements

- Attach to all syscalls dynamically
- Add PID filtering
- Add error-rate tracking (ret < 0)
- Add latency histogram (log2 buckets)
- Add container / cgroup support
- Port to Go + libbpf (CO-RE)

---

## License

MIT License (recommended)

