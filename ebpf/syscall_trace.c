/* Specter-Net eBPF syscall tracer */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct syscall_event { u32 pid; u64 syscall_nr; u64 timestamp; char comm[16]; };
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); } events SEC(".maps");
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall(void *ctx) {
    struct syscall_event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    return 0;
}
char _license[] SEC("license") = "GPL";
