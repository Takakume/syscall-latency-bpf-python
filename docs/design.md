# Design

## Measurement model

- tracepoint: sys_enter
- tracepoint: sys_exit
- measure latency with bpf_ktime_get_ns()

## Maps

### start
key: pid_tgid
value: timestamp

### stats
key: syscall ID
value:
  - count
  - total_ns
  - max_ns

## Why tracepoints instead of kprobe?

Tracepoints are stable across kernel versions and safer for production use.
