# syscall-latency-bpf

A minimal syscall latency profiler built with eBPF (BCC).

------------------------------------------------------------------------

## Motivation

When investigating performance issues, `perf` often produces noisy call
stacks.

In many cases, what we really want to know is:

> **Which syscall is slow, and which process is causing it?**

This tool aggregates syscall latency directly in the kernel and reports:

-   Process ID (PID)
-   Call count
-   Average latency
-   Maximum latency

It focuses purely on syscall latency instead of full stack profiling.

------------------------------------------------------------------------

## Architecture

This tool uses:

-   eBPF (BCC)
-   kprobe / kretprobe
-   In-kernel hash maps for aggregation

Latency is measured using:

    bpf_ktime_get_ns()

Measurement pattern:

1.  kprobe (syscall entry)
    -   Store timestamp and syscall ID in `start` map
2.  kretprobe (syscall exit)
    -   Calculate latency delta
    -   Update aggregated statistics in `stats` map (keyed by syscall +
        PID)

------------------------------------------------------------------------

## Data Flow

    Userspace (Python)
            ↓
        eBPF Program
            ↓
      kprobe / kretprobe
            ↓
         BPF Maps
            ↓
       Aggregated Output (on Ctrl+C)

All aggregation happens inside the kernel to minimize overhead.

------------------------------------------------------------------------

## BPF Maps

### start

Temporary map storing the start time of in-flight syscalls.

  Key        Value
  ---------- ---------------------------
  pid_tgid   { timestamp, syscall ID }

Structure:

``` c
struct start_t {
    u64 ts;
    u32 id;
};
```

------------------------------------------------------------------------

### stats

Aggregated statistics per **(syscall ID, PID)**.

  Key                   Value
  --------------------- -------------------------
  { syscall ID, PID }   count, total_ns, max_ns

Structures:

``` c
struct key_t {
    u32 id;
    u32 pid;
};

struct stats_t {
    u64 count;
    u64 total_ns;
    u64 max_ns;
};
```

------------------------------------------------------------------------

## Example Output

    read
    ------------------------------------------------------------
    PID        COUNT      AVG(us)      MAX(us)
    1616       10         4.42         5.19
    1400       24         7.65         48.52
    1644       10         3096369.70   30963645.22

------------------------------------------------------------------------

## Installation

    sudo dnf install -y bcc python3-bcc kernel-devel clang llvm

------------------------------------------------------------------------

## Usage

    sudo python3 syscall_latency.py

Press `Ctrl+C` to print aggregated statistics.

------------------------------------------------------------------------

## License

MIT License
